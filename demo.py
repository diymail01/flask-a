import streamlit as st
import pandas as pd
import sqlite3
import subprocess
import socket
import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import io
import re
import os
import ssl
import requests
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import smtplib
import json
from typing import List, Dict, Tuple, Optional


# Initialize SQLite database
def init_db():
    """Initialize database with proper error handling"""
    try:
        conn = sqlite3.connect('compliance_results.db')
        c = conn.cursor()
        
        # Create table with all required columns
        c.execute('''CREATE TABLE IF NOT EXISTS compliance_results
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      scan_date TIMESTAMP,
                      service_type TEXT,
                      ip_address TEXT,
                      domain TEXT,
                      sr_no INTEGER,
                      parameter TEXT,
                      compliance_status TEXT,
                      threat_level TEXT,
                      remarks TEXT,
                      command_used TEXT,
                      hostname TEXT,
                      target_type TEXT)''')
        
        # Check if table needs column updates
        cursor = c.execute("PRAGMA table_info(compliance_results)")
        columns = [column[1] for column in cursor.fetchall()]
        
        # Add missing columns if needed
        if 'hostname' not in columns:
            c.execute('ALTER TABLE compliance_results ADD COLUMN hostname TEXT')
        
        if 'target_type' not in columns:
            c.execute('ALTER TABLE compliance_results ADD COLUMN target_type TEXT')
        
        conn.commit()
        conn.close()
        return True
        
    except Exception as e:
        print(f"Database initialization error: {e}")
        try:
            conn.close()
        except:
            pass
        return False
    
# Common ports for different services
COMMON_PORTS = {
    'web': [80, 443, 8080, 8443],
    'mail': [25, 110, 143, 465, 587, 993, 995],
    'ftp': [20, 21, 990],
    'ssh': [22],
    'telnet': [23],
    'dns': [53],
    'database': [1433, 1521, 3306, 5432, 27017],
    'remote': [3389, 5900],
    'management': [161, 162, 10000],
    'top_1000': "1-1000"  # Most common ports
}

# Complete compliance parameters from the provided list
COMPLIANCE_TYPES = {
    "UTM / Switch / Router": {
        "parameters": [
            {
                "sr_no": 1,
                "parameter": "List the Open Ports on the IP Address",
                "command": "nmap -Pn -sV -O {ip} --top-ports 1000",
                "threat_level": "Info",
                "check_function": "check_open_ports"
            },
            {
                "sr_no": 2,
                "parameter": "The management port of UTM or Switch should not be accessible on the IP Address",
                "command": "nmap -A -T4 -Pn -p 443,80,22,21,25 {ip}",
                "threat_level": "Medium",
                "check_function": "check_management_ports"
            },
            {
                "sr_no": 3,
                "parameter": "The Login of UTM/Switch/Router shall not be visible on Internet",
                "command": "nmap -A -T4 -Pn -p 443,80,22,21,25 {ip}",
                "threat_level": "High",
                "check_function": "check_login_visibility"
            },
            {
                "sr_no": 4,
                "parameter": "List the observed service(s) operational on the IP Address",
                "command": "nmap -Pn -sV -O {ip} --top-ports 100",
                "threat_level": "Info",
                "check_function": "check_services"
            },
            {
                "sr_no": 5,
                "parameter": "The service's version running on the IP Address should not be visible",
                "command": "nmap -Pn -sV {ip} --top-ports 100",
                "threat_level": "Medium",
                "check_function": "check_version_disclosure"
            }
        ]
    },
    "SSH Service": {
        "parameters": [
            {
                "sr_no": 1,
                "parameter": "List the Open Ports on the IP Address",
                "command": "nmap -Pn -sV -O {ip} --top-ports 100",
                "threat_level": "Info",
                "check_function": "check_ssh_ports"
            },
            {
                "sr_no": 2,
                "parameter": "SSH service version should not be visible on the IP Address",
                "command": "nmap -Pn -sV -p 22 {ip}",
                "threat_level": "Medium",
                "check_function": "check_ssh_version"
            },
            {
                "sr_no": 3,
                "parameter": "SSH service should not run using protocol version 1.x",
                "command": "ssh-audit {ip}",
                "threat_level": "High",
                "check_function": "check_ssh_protocol"
            },
            {
                "sr_no": 4,
                "parameter": "SSH service should support strong ciphers",
                "command": "ssh-audit {ip}",
                "threat_level": "Low",
                "check_function": "check_ssh_ciphers"
            },
            {
                "sr_no": 5,
                "parameter": "SSH service should support strong key algorithms",
                "command": "ssh-audit {ip}",
                "threat_level": "Low",
                "check_function": "check_ssh_key_algorithms"
            },
            {
                "sr_no": 6,
                "parameter": "SSH service should support strong Message Authentication Code (MAC) algorithms for data integrity",
                "command": "ssh-audit {ip}",
                "threat_level": "Low",
                "check_function": "check_ssh_mac"
            }
        ]
    },
    "FTP Service": {
        "parameters": [
            {
                "sr_no": 1,
                "parameter": "List the Open Ports on the IP Address",
                "command": "nmap -Pn -sV -O {ip} --top-ports 100",
                "threat_level": "Info",
                "check_function": "check_ftp_ports"
            },
            {
                "sr_no": 2,
                "parameter": "Is FTP service accessible on the IP Address?",
                "command": "nmap -Pn -sV -p 21 {ip}",
                "threat_level": "Info",
                "check_function": "check_ftp_accessible"
            },
            {
                "sr_no": 3,
                "parameter": "FTP service version should not be visible on the IP Address",
                "command": "nmap -Pn -sV -p 21 {ip}",
                "threat_level": "Medium",
                "check_function": "check_ftp_version"
            },
            {
                "sr_no": 4,
                "parameter": "FTP service should be accessible over secure channel",
                "command": "nmap -Pn -sC -sV -p 21,990 {ip}",
                "threat_level": "Low",
                "check_function": "check_ftp_secure"
            },
            {
                "sr_no": 5,
                "parameter": "Anonymous FTP upload should not be allowed",
                "command": "nmap -Pn --script ftp-anon -p 21 {ip}",
                "threat_level": "Medium",
                "check_function": "check_ftp_anonymous"
            }
        ]
    },
    "DNS Server": {
        "parameters": [
            {
                "sr_no": 1,
                "parameter": "Open ports for DNS server other than required to run DNS",
                "command": "nmap -Pn -sV -O {ip} --top-ports 100",
                "threat_level": "Info",
                "check_function": "check_dns_ports"
            },
            {
                "sr_no": 2,
                "parameter": "DNS version shall not be visible",
                "command": "nmap -Pn -sU -p 53 --script dns-nsid {ip}",
                "threat_level": "Medium",
                "check_function": "check_dns_version"
            },
            {
                "sr_no": 3,
                "parameter": "DNS server shall not support recursion (open recursive or open resolver)",
                "command": "nmap --script=dns-recursion -sU -Pn -p 53 {ip}",
                "threat_level": "High",
                "check_function": "check_dns_recursion"
            },
            {
                "sr_no": 4,
                "parameter": "All DNS resolving servers use sufficiently random port and transaction id in query",
                "command": "nmap -sU -p 53 --script dns-random-srcport {ip}",
                "threat_level": "High",
                "check_function": "check_dns_randomization"
            },
            {
                "sr_no": 5,
                "parameter": "DNSSEC should be implemented on DNS",
                "command": "dig @{ip} +dnssec +multi",
                "threat_level": "Info",
                "check_function": "check_dnssec"
            },
            {
                "sr_no": 6,
                "parameter": "DNSSEC shall be implemented using RSA256 (applicable only if implemented)",
                "command": "dig @{ip} DNSKEY +dnssec",
                "threat_level": "Low",
                "check_function": "check_dnssec_rsa256"
            },
            {
                "sr_no": 7,
                "parameter": "If DNSSEC is implemented, NSEC-walking shall be disabled",
                "command": "nmap -sU -p 53 --script dns-nsec-enum {ip}",
                "threat_level": "Medium",
                "check_function": "check_nsec_walking"
            },
            {
                "sr_no": 8,
                "parameter": "SPF record shall be published in DNS with \"-all\" parameter",
                "command": "dig TXT {domain}",
                "threat_level": "High",
                "check_function": "check_spf_record"
            },
            {
                "sr_no": 9,
                "parameter": "DMARC record shall be published in DNS",
                "command": "dig TXT _dmarc.{domain}",
                "threat_level": "High",
                "check_function": "check_dmarc_record"
            },
            {
                "sr_no": 10,
                "parameter": "DKIM record shall be published in DNS",
                "command": "dig TXT default._domainkey.{domain}",
                "threat_level": "High",
                "check_function": "check_dkim_record"
            },
            {
                "sr_no": 11,
                "parameter": "CAA record should be published in DNS",
                "command": "dig CAA {domain}",
                "threat_level": "Info",
                "check_function": "check_caa_record"
            },
            {
                "sr_no": 12,
                "parameter": "Un-protected zone transfers shall be disabled",
                "command": "nmap -sn -Pn --script dns-zone-transfer.nse {ip}",
                "threat_level": "High",
                "check_function": "check_zone_transfer"
            }
        ]
    },
    "Email Service": {
        "parameters": [
            {
                "sr_no": 1,
                "parameter": "The email server shall not act as relay server from Internet",
                "command": "swaks --server {ip} --from user@gmail.com --to user@yahoo.com",
                "threat_level": "High",
                "check_function": "check_email_relay"
            },
            {
                "sr_no": 2,
                "parameter": "The Mail Transfer Agent (MTA) version shall not be visible",
                "command": "nmap -sV -p 25 {ip}",
                "threat_level": "Medium",
                "check_function": "check_mta_version"
            },
            {
                "sr_no": 3,
                "parameter": "The MTA software shall not be old/discontinued version",
                "command": "nmap -sV -p 25 {ip}",
                "threat_level": "Info",
                "check_function": "check_mta_old_version"
            },
            {
                "sr_no": 4,
                "parameter": "MTA should support TLS",
                "command": "nmap -sV -p 25 {ip}",
                "threat_level": "Info",
                "check_function": "check_mta_tls"
            },
            {
                "sr_no": 5,
                "parameter": "SMTP-AUTH shall be disabled on MX server",
                "command": "telnet {ip} 25",
                "threat_level": "Low",
                "check_function": "check_smtp_auth"
            },
            {
                "sr_no": 6,
                "parameter": "User enumeration shall be disabled (VRFY command)",
                "command": "telnet {ip} 25",
                "threat_level": "Medium",
                "check_function": "check_user_enumeration"
            },
            {
                "sr_no": 7,
                "parameter": "The mail server shall block incoming mail with own domain spoofed",
                "command": "swaks -f user1@{domain} -t user2@{domain}",
                "threat_level": "High",
                "check_function": "check_domain_spoofing"
            },
            {
                "sr_no": 8,
                "parameter": "The mail server shall block incoming mail with own domain spoofed using punny code",
                "command": "swaks -f user1@{domain} -t user2@{domain}",
                "threat_level": "High",
                "check_function": "check_punny_code_spoofing"
            },
            {
                "sr_no": 9,
                "parameter": "The mail server shall block incoming mail with own sub-domain spoofed",
                "command": "swaks -f user1@subdomain.{domain} -t user2@{domain}",
                "threat_level": "High",
                "check_function": "check_subdomain_spoofing"
            },
            {
                "sr_no": 10,
                "parameter": "The mail server shall block incoming mail with own sub-domain spoofed using punny code",
                "command": "swaks -f user1@subdomain.{domain} -t user2@{domain}",
                "threat_level": "High",
                "check_function": "check_subdomain_punny_spoofing"
            },
            {
                "sr_no": 11,
                "parameter": "The mail server shall block incoming mail with own sub domain spoofed",
                "command": "swaks -f user1@subdomain.{domain} -t user2@{domain}",
                "threat_level": "High",
                "check_function": "check_subdomain_block"
            },
            {
                "sr_no": 12,
                "parameter": "The MTA shall reject mails from Dynamic/Poor Reputation IPs",
                "command": "Custom check for RBL",
                "threat_level": "Low",
                "check_function": "check_rbl_rejection"
            },
            {
                "sr_no": 13,
                "parameter": "Check Reverse and Forward DNS match of mailserver hostname",
                "command": "dig -x {ip} && nslookup hostname",
                "threat_level": "Low",
                "check_function": "check_dns_match"
            }
        ]
    },
    "Web Application": {
        "parameters": [
            {
                "sr_no": 1,
                "parameter": "List the Open Ports on the IP Address",
                "command": "nmap -Pn -sV -O {ip} --top-ports 100",
                "threat_level": "Info",
                "check_function": "check_web_ports"
            },
            {
                "sr_no": 2,
                "parameter": "Web service must run on https",
                "command": "nmap -Pn -sV -p 80,443 {ip}",
                "threat_level": "Low",
                "check_function": "check_https_required"
            },
            {
                "sr_no": 3,
                "parameter": "Header: Web service version must not be visible",
                "command": "curl -I http://{ip}",
                "threat_level": "Medium",
                "check_function": "check_web_version_disclosure"
            },
            {
                "sr_no": 4,
                "parameter": "Header: PHP/CMS/Other software version display is disabled",
                "command": "curl -I http://{ip}",
                "threat_level": "Medium",
                "check_function": "check_software_version_headers"
            },
            {
                "sr_no": 5,
                "parameter": "TLSv 1.0, SSLv2, SSLv3 support must be disabled",
                "command": "nmap --script ssl-enum-ciphers -p 443 {ip}",
                "threat_level": "High",
                "check_function": "check_deprecated_ssl"
            },
            {
                "sr_no": 6,
                "parameter": "Remote Login of Content Management System (CMS) like Drupal, Joomla, Wordpress etc. or Site Management or Tomcat Manager shall not accessible over Internet",
                "command": "nmap -Pn -sC -sV -p 80,443 {ip}",
                "threat_level": "Medium",
                "check_function": "check_cms_admin_access"
            },
            {
                "sr_no": 7,
                "parameter": "Check other vulnerability like Cross-site scripting / SQL injection etc.",
                "command": "Custom vulnerability scan",
                "threat_level": "High/Medium/Low",
                "check_function": "check_web_vulnerabilities"
            },
            {
                "sr_no": 8,
                "parameter": "Check other vulnerability like Cross-site scripting / SQL injection etc. for the sites hosted through CDN also",
                "command": "Custom vulnerability scan with CDN check",
                "threat_level": "High/Medium/Low",
                "check_function": "check_cdn_vulnerabilities"
            }
        ]
    }
}

# Helper function for socket-based SMTP communication
def smtp_send_recv(sock, command, timeout=5):
    """Send command and receive response from SMTP server"""
    try:
        if command:
            sock.send(command.encode() + b'\r\n')
        
        # Receive response
        sock.settimeout(timeout)
        response = b''
        while True:
            data = sock.recv(1024)
            if not data:
                break
            response += data
            if b'\r\n' in data:
                break
        
        return response.decode('utf-8', errors='ignore')
    except socket.timeout:
        return ""
    except Exception as e:
        return f"Error: {str(e)}"

# Quick port scanner for specific ports
def quick_port_scan(ip, ports, timeout=1):
    """Quick scan for specific ports"""
    if not ports:
        return []
    
    open_ports = []
    
    def scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return port
            return None
        except Exception:
            return None
    
    try:
        # Use threading for faster scanning
        with ThreadPoolExecutor(max_workers=min(50, len(ports))) as executor:
            futures = [executor.submit(scan_port, port) for port in ports]
            for future in as_completed(futures):
                try:
                    port = future.result()
                    if port:
                        open_ports.append(port)
                except Exception:
                    # Skip failed port scans
                    continue
        
        return sorted(open_ports) if open_ports else []
        
    except Exception:
        # If threading fails, return empty list instead of None
        return []
    
# ============== AUTO-DISCOVERY FUNCTIONS ==============

def is_valid_domain(domain: str) -> bool:
    """Check if input is a valid domain name"""
    if not domain or len(domain) > 255:
        return False
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return bool(re.match(domain_pattern, domain))

def is_valid_ip(ip: str) -> bool:
    """Check if input is a valid IP address"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def smart_input_parser(input_text: str) -> Dict:
    """Parse input and determine if it's domain, IP, or mixed"""
    input_text = input_text.strip()
    
    if not input_text:
        return {'type': 'empty', 'items': []}
    
    items = [item.strip() for item in input_text.split(',')]
    
    parsed_items = []
    for item in items:
        if is_valid_ip(item):
            parsed_items.append({'type': 'ip', 'value': item})
        elif is_valid_domain(item):
            parsed_items.append({'type': 'domain', 'value': item})
        else:
            parsed_items.append({'type': 'invalid', 'value': item})
    
    types = [item['type'] for item in parsed_items]
    if all(t == 'ip' for t in types):
        return {'type': 'ip_only', 'items': parsed_items}
    elif all(t == 'domain' for t in types):
        return {'type': 'domain_only', 'items': parsed_items}
    elif 'invalid' in types:
        return {'type': 'invalid', 'items': parsed_items}
    else:
        return {'type': 'mixed', 'items': parsed_items}

def discover_dns_servers(domain: str) -> Dict:
    """Auto-discover DNS servers for a given domain"""
    result = {
        'domain': domain,
        'success': False,
        'dns_servers': [],
        'errors': [],
        'discovery_method': None
    }
    
    try:
        # Method 1: Get authoritative DNS servers using NS records
        try:
            ns_result = subprocess.run(
                ['dig', '+short', 'NS', domain], 
                capture_output=True, text=True, timeout=10
            )
            
            if ns_result.returncode == 0 and ns_result.stdout.strip():
                ns_servers = [line.strip().rstrip('.') for line in ns_result.stdout.strip().split('\n') if line.strip()]
                
                if ns_servers:
                    result['discovery_method'] = 'NS_records'
                    
                    for ns_server in ns_servers:
                        try:
                            ip_result = subprocess.run(
                                ['dig', '+short', 'A', ns_server], 
                                capture_output=True, text=True, timeout=5
                            )
                            
                            if ip_result.returncode == 0 and ip_result.stdout.strip():
                                ips = [ip.strip() for ip in ip_result.stdout.strip().split('\n') if ip.strip() and is_valid_ip(ip.strip())]
                                
                                for ip in ips:
                                    server_info = {
                                        'hostname': ns_server,
                                        'ip': ip,
                                        'type': 'authoritative',
                                        'source': 'NS_record'
                                    }
                                    result['dns_servers'].append(server_info)
                        except Exception as e:
                            result['errors'].append(f"Failed to resolve NS server {ns_server}: {str(e)}")
                    
                    if result['dns_servers']:
                        result['success'] = True
                        return result
        
        except Exception as e:
            result['errors'].append(f"NS record lookup failed: {str(e)}")
        
        if not result['success']:
            result['errors'].append("No DNS servers could be auto-discovered for this domain")
            result['discovery_method'] = 'failed'
    
    except Exception as e:
        result['errors'].append(f"Discovery process failed: {str(e)}")
    
    return result

def discover_mail_servers(domain: str) -> Dict:
    """Auto-discover mail servers for a given domain"""
    result = {
        'domain': domain,
        'success': False,
        'mail_servers': [],
        'errors': [],
        'discovery_method': None
    }
    
    try:
        # Get MX records
        mx_result = subprocess.run(
            ['dig', '+short', 'MX', domain], 
            capture_output=True, text=True, timeout=10
        )
        
        if mx_result.returncode == 0 and mx_result.stdout.strip():
            mx_lines = [line.strip() for line in mx_result.stdout.strip().split('\n') if line.strip()]
            
            mx_servers = []
            for line in mx_lines:
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        priority = int(parts[0])
                        hostname = parts[1].rstrip('.')
                        mx_servers.append((priority, hostname))
                    except ValueError:
                        continue
            
            if mx_servers:
                result['discovery_method'] = 'MX_records'
                mx_servers.sort(key=lambda x: x[0])  # Sort by priority
                
                for priority, mx_hostname in mx_servers:
                    try:
                        ip_result = subprocess.run(
                            ['dig', '+short', 'A', mx_hostname], 
                            capture_output=True, text=True, timeout=5
                        )
                        
                        if ip_result.returncode == 0 and ip_result.stdout.strip():
                            ips = [ip.strip() for ip in ip_result.stdout.strip().split('\n') if ip.strip() and is_valid_ip(ip.strip())]
                            
                            for ip in ips:
                                server_info = {
                                    'hostname': mx_hostname,
                                    'ip': ip,
                                    'priority': priority,
                                    'type': 'mx_server',
                                    'source': 'MX_record'
                                }
                                result['mail_servers'].append(server_info)
                    except Exception as e:
                        result['errors'].append(f"Failed to resolve MX server {mx_hostname}: {str(e)}")
                
                if result['mail_servers']:
                    result['success'] = True
                    return result
        
        if not result['success']:
            result['errors'].append("No mail servers could be auto-discovered for this domain")
            result['discovery_method'] = 'failed'
    
    except Exception as e:
        result['errors'].append(f"Discovery process failed: {str(e)}")
    
    return result

def discover_web_servers(domain: str) -> Dict:
    """Auto-discover web servers for a given domain"""
    result = {
        'domain': domain,
        'success': False,
        'web_servers': [],
        'errors': [],
        'discovery_method': None
    }
    
    try:
        # Get A records
        a_result = subprocess.run(
            ['dig', '+short', 'A', domain], 
            capture_output=True, text=True, timeout=10
        )
        
        if a_result.returncode == 0 and a_result.stdout.strip():
            ips = [ip.strip() for ip in a_result.stdout.strip().split('\n') if ip.strip() and is_valid_ip(ip.strip())]
            
            if ips:
                result['discovery_method'] = 'A_records'
                
                for ip in ips:
                    server_info = {
                        'hostname': domain,
                        'ip': ip,
                        'type': 'web_server',
                        'source': 'A_record',
                        'ports_detected': []
                    }
                    
                    # Test common web ports
                    web_ports = [80, 443, 8080, 8443]
                    for port in web_ports:
                        try:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(3)
                            result_code = sock.connect_ex((ip, port))
                            sock.close()
                            if result_code == 0:
                                server_info['ports_detected'].append(port)
                        except:
                            continue
                    
                    if server_info['ports_detected']:
                        result['web_servers'].append(server_info)
                
                if result['web_servers']:
                    result['success'] = True
                    return result
        
        if not result['success']:
            result['errors'].append("No web servers could be auto-discovered for this domain")
            result['discovery_method'] = 'failed'
    
    except Exception as e:
        result['errors'].append(f"Discovery process failed: {str(e)}")
    
    return result

def auto_discover_targets(service_type: str, input_text: str) -> Dict:
    """Main function to auto-discover targets based on service type and input"""
    parsed_input = smart_input_parser(input_text)
    
    result = {
        'service_type': service_type,
        'input_text': input_text,
        'parsed_input': parsed_input,
        'discovered_targets': [],
        'manual_targets': [],
        'errors': [],
        'requires_user_selection': False
    }
    
    if service_type == "DNS Server":
        for item in parsed_input['items']:
            if item['type'] == 'domain':
                discovery_result = discover_dns_servers(item['value'])
                if discovery_result['success']:
                    result['discovered_targets'].extend(discovery_result['dns_servers'])
                else:
                    result['errors'].extend(discovery_result['errors'])
            elif item['type'] == 'ip':
                result['manual_targets'].append({
                    'hostname': 'manual',
                    'ip': item['value'],
                    'type': 'manual_dns',
                    'source': 'user_input'
                })
    
    elif service_type == "Email Service":
        for item in parsed_input['items']:
            if item['type'] == 'domain':
                discovery_result = discover_mail_servers(item['value'])
                if discovery_result['success']:
                    result['discovered_targets'].extend(discovery_result['mail_servers'])
                else:
                    result['errors'].extend(discovery_result['errors'])
            elif item['type'] == 'ip':
                result['manual_targets'].append({
                    'hostname': 'manual',
                    'ip': item['value'],
                    'priority': 999,
                    'type': 'manual_mail',
                    'source': 'user_input'
                })
    
    elif service_type == "Web Application":
        for item in parsed_input['items']:
            if item['type'] == 'domain':
                discovery_result = discover_web_servers(item['value'])
                if discovery_result['success']:
                    result['discovered_targets'].extend(discovery_result['web_servers'])
                else:
                    result['errors'].extend(discovery_result['errors'])
            elif item['type'] == 'ip':
                result['manual_targets'].append({
                    'hostname': 'manual',
                    'ip': item['value'],
                    'type': 'manual_web',
                    'source': 'user_input'
                })
    
    else:
        # For other services, keep existing manual IP behavior
        for item in parsed_input['items']:
            if item['type'] == 'ip':
                result['manual_targets'].append({
                    'hostname': 'manual',
                    'ip': item['value'],
                    'type': 'manual',
                    'source': 'user_input'
                })
            else:
                result['errors'].append(f"Service type {service_type} requires IP addresses, not domains")
    
    total_targets = len(result['discovered_targets']) + len(result['manual_targets'])
    if total_targets > 1:
        result['requires_user_selection'] = True
    
    return result
    
    # Use threading for faster scanning
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(scan_port, port) for port in ports]
        for future in as_completed(futures):
            port = future.result()
            if port:
                open_ports.append(port)
    
    return sorted(open_ports)

# Check functions implementation
def check_open_ports(ip, domain=None):
    """List open ports using quick scan of top ports"""
    try:
        # Quick scan of most common ports
        top_ports = list(range(1, 1001))  # Top 1000 ports
        additional_ports = [3306, 3389, 5432, 5900, 8080, 8443, 10000, 27017]
        all_ports = list(set(top_ports + additional_ports))
        
        st.text(f"Scanning top {len(all_ports)} ports...")
        open_ports = quick_port_scan(ip, all_ports, timeout=0.5)
        
        if open_ports:
            # Try to identify services on open ports using nmap for just the open ports
            port_list = ','.join(map(str, open_ports[:20]))  # Limit to first 20 ports
            try:
                result = subprocess.run(['nmap', '-Pn', '-sV', '-p', port_list, ip], 
                                      capture_output=True, text=True, timeout=30)
                
                # Parse nmap output for service info
                services = []
                for line in result.stdout.split('\n'):
                    if '/tcp' in line and 'open' in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            port = parts[0].split('/')[0]
                            service = parts[2]
                            version = ' '.join(parts[3:]) if len(parts) > 3 else ''
                            services.append(f"{port}/tcp ({service} {version})".strip())
                
                if services:
                    return "-", f"Open ports: {', '.join(services)}"
                else:
                    return "-", f"Open ports: {', '.join(map(str, open_ports))}"
            except:
                return "-", f"Open ports: {', '.join(map(str, open_ports))}"
        else:
            return "-", "No open ports found in top 1000 ports"
    except Exception as e:
        return "Error", f"Failed to scan: {str(e)}"

check_ssh_ports = check_ftp_ports = check_web_ports = check_open_ports

def check_management_ports(ip, domain=None):
    """Check if management ports are accessible"""
    try:
        mgmt_ports = [22, 23, 80, 443, 3389, 5900, 8080, 8443, 10000]
        open_mgmt_ports = quick_port_scan(ip, mgmt_ports)
        
        if open_mgmt_ports:
            return "No", f"Management ports accessible: {', '.join(map(str, open_mgmt_ports))}"
        return "Yes", "No management ports accessible"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_login_visibility(ip, domain=None):
    """Check if login interface is visible"""
    try:
        # Check common web ports
        web_ports = quick_port_scan(ip, [80, 443, 8080, 8443])
        
        # Handle case where quick_port_scan returns None
        if web_ports is None:
            web_ports = []
        
        login_found = []
        
        # Only proceed if we have open web ports
        if web_ports:
            for port in web_ports:
                try:
                    protocol = 'https' if port in [443, 8443] else 'http'
                    
                    # Add timeout and handle SSL verification issues
                    import requests
                    from requests.packages.urllib3.exceptions import InsecureRequestWarning
                    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
                    
                    response = requests.get(
                        f"{protocol}://{ip}:{port}", 
                        timeout=5, 
                        verify=False, 
                        allow_redirects=True,
                        headers={'User-Agent': 'Mozilla/5.0 (Security Scanner)'}
                    )
                    
                    # Check for login indicators in response
                    login_keywords = ['login', 'signin', 'sign-in', 'admin', 'dashboard', 
                                    'username', 'password', 'authenticate', 'log in']
                    
                    content_lower = response.text.lower()
                    found_keyword = None
                    for keyword in login_keywords:
                        if keyword in content_lower:
                            found_keyword = keyword
                            break
                    
                    if found_keyword:
                        login_found.append(f"Port {port} ({found_keyword} found)")
                    
                    # Check common login paths
                    login_paths = ['/admin', '/login', '/wp-admin', '/administrator', 
                                 '/manager', '/console', '/management']
                    
                    for path in login_paths:
                        try:
                            url = f"{protocol}://{ip}:{port}{path}"
                            resp = requests.get(
                                url, 
                                timeout=3, 
                                verify=False, 
                                allow_redirects=False,
                                headers={'User-Agent': 'Mozilla/5.0 (Security Scanner)'}
                            )
                            
                            if resp.status_code in [200, 401, 403]:
                                login_found.append(f"Port {port} ({path} accessible)")
                                break  # Found one path, no need to check others for this port
                                
                        except requests.exceptions.RequestException:
                            # Continue to next path if this one fails
                            continue
                        except Exception:
                            # Continue to next path if any other error occurs
                            continue
                            
                except requests.exceptions.RequestException as req_err:
                    # Handle specific request errors (timeout, connection, etc.)
                    continue
                except Exception as e:
                    # Handle any other exceptions and continue
                    continue
        
        # Check SSH/Telnet ports separately
        try:
            ssh_telnet_ports = quick_port_scan(ip, [22, 23])
            if ssh_telnet_ports is None:
                ssh_telnet_ports = []
                
            if 22 in ssh_telnet_ports:
                login_found.append("SSH (port 22)")
            if 23 in ssh_telnet_ports:
                login_found.append("Telnet (port 23)")
                
        except Exception:
            # If SSH/Telnet check fails, continue without it
            pass
        
        # Return results
        if login_found:
            return "No", f"Login interfaces visible: {'; '.join(login_found)}"
        return "Yes", "No login interface visible on Internet"
        
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"
    
def check_services(ip, domain=None):
    """List services running on the IP"""
    return check_open_ports(ip, domain)

def check_version_disclosure(ip, domain=None):
    """Check if service versions are visible"""
    try:
        # Quick scan of common ports
        common_ports = [21, 22, 23, 25, 80, 110, 143, 443, 3306, 3389, 5432]
        open_ports = quick_port_scan(ip, common_ports)
        
        if not open_ports:
            return "Yes", "No services detected"
        
        # Use nmap to check versions on open ports only
        port_list = ','.join(map(str, open_ports))
        result = subprocess.run(['nmap', '-Pn', '-sV', '-p', port_list, ip], 
                              capture_output=True, text=True, timeout=30)
        
        visible_versions = []
        for line in result.stdout.split('\n'):
            if 'open' in line and ('Version' in line or re.search(r'\d+\.\d+', line)):
                parts = line.split()
                if len(parts) >= 4:
                    port = parts[0]
                    service = parts[2]
                    version = ' '.join(parts[3:])
                    if version and version != 'tcpwrapped':
                        visible_versions.append(f"{service} on {port}")
        
        if visible_versions:
            return "No", f"Version visible for: {'; '.join(visible_versions[:5])}"
        return "Yes", "Service versions are not visible"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_ssh_version(ip, domain=None):
    """Check if SSH version is visible"""
    try:
        # First check if SSH port is open
        if not quick_port_scan(ip, [22]):
            return "N/A", "SSH port not open"
        
        # Get SSH banner
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, 22))
        
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()
        
        if 'SSH-' in banner:
            # Extract version info
            version_match = re.search(r'SSH-[\d.]+-(.+)', banner)
            if version_match:
                version_info = version_match.group(1).strip()
                if re.search(r'\d+\.\d+', version_info):  # Contains version numbers
                    return "No", f"SSH version visible: {version_info}"
                else:
                    return "Yes", f"SSH banner present but version hidden: {banner.strip()}"
        
        return "Yes", "SSH version not visible"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_ssh_version(ip, domain=None):
    """Check if SSH version is visible"""
    try:
        # Check multiple possible SSH ports
        ssh_ports = [22, 2222, 2022]
        ssh_port = None
        
        for port in ssh_ports:
            if quick_port_scan(ip, [port], timeout=2):
                ssh_port = port
                break
        
        if not ssh_port:
            return "N/A", "No SSH service detected on common ports (22, 2222, 2022)"
        
        # Get SSH banner
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, ssh_port))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            if 'SSH-' in banner:
                # Extract version info
                version_match = re.search(r'SSH-[\d.]+-(.+)', banner)
                if version_match:
                    version_info = version_match.group(1).strip()
                    # Check if version contains specific version numbers
                    if re.search(r'\d+\.\d+', version_info):
                        return "No", f"SSH version visible on port {ssh_port}: {version_info}"
                    else:
                        return "Yes", f"SSH banner present on port {ssh_port} but version hidden: {banner}"
                else:
                    return "Yes", f"SSH service detected on port {ssh_port} but version format unclear: {banner}"
            else:
                return "Error", f"Port {ssh_port} open but no SSH banner received"
        
        except socket.timeout:
            return "Error", f"Connection timeout to SSH port {ssh_port}"
        except ConnectionRefusedError:
            return "N/A", f"Connection refused on port {ssh_port} (service may have stopped)"
        except Exception as e:
            return "Error", f"Failed to connect to SSH port {ssh_port}: {str(e)}"
            
    except Exception as e:
        return "Error", f"SSH version check failed: {str(e)}"


def check_ssh_protocol(ip, domain=None):
    """Check if SSH protocol version 1 is supported"""
    try:
        # Check multiple possible SSH ports
        ssh_ports = [22, 2222, 2022]
        ssh_port = None
        
        for port in ssh_ports:
            if quick_port_scan(ip, [port], timeout=2):
                ssh_port = port
                break
        
        if not ssh_port:
            return "N/A", "No SSH service detected on common ports (22, 2222, 2022)"
        
        # Try ssh-audit if available (better method)
        try:
            result = subprocess.run(['ssh-audit', '-1', ip], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                output_lower = result.stdout.lower()
                if "ssh1" in output_lower or "protocol 1" in output_lower:
                    return "No", f"SSH protocol version 1 is supported on port {ssh_port} (insecure)"
                elif "ssh2" in output_lower or "protocol 2" in output_lower:
                    return "Yes", f"Only SSH protocol version 2 is supported on port {ssh_port}"
                else:
                    return "N/A", f"SSH-audit completed but protocol version unclear"
        except FileNotFoundError:
            pass  # ssh-audit not available, try manual method
        except subprocess.TimeoutExpired:
            pass  # ssh-audit timed out
        
        # Fallback: Try to connect with SSH-1.5 banner
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, ssh_port))
            
            # Get server banner first
            server_banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            # Send SSH-1.5 client banner
            sock.send(b'SSH-1.5-TestClient\r\n')
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            if 'SSH-1' in response:
                return "No", f"SSH protocol version 1 is supported on port {ssh_port}"
            elif 'Protocol major versions differ' in response or 'SSH-2' in response:
                return "Yes", f"Only SSH protocol version 2 is supported on port {ssh_port}"
            elif server_banner and 'SSH-2' in server_banner:
                return "Yes", f"SSH-2 only (based on server banner: {server_banner})"
            else:
                return "Yes", f"SSH-1 not supported on port {ssh_port} (server response indicates SSH-2 only)"
                
        except Exception as e:
            return "Error", f"Protocol version test failed on port {ssh_port}: {str(e)}"
            
    except Exception as e:
        return "Error", f"SSH protocol check failed: {str(e)}"


def check_ssh_ciphers(ip, domain=None):
    """Check SSH cipher strength"""
    try:
        # Check multiple possible SSH ports
        ssh_ports = [22, 2222, 2022]
        ssh_port = None
        
        for port in ssh_ports:
            if quick_port_scan(ip, [port], timeout=2):
                ssh_port = port
                break
        
        if not ssh_port:
            return "N/A", "No SSH service detected on common ports (22, 2222, 2022)"
        
        # Try ssh-audit
        try:
            # Try with port specification
            result = subprocess.run(['ssh-audit', f'{ip}:{ssh_port}'], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                weak_ciphers = ['3des', 'arcfour', 'des', 'rc4', 'blowfish', 'cast128']
                found_weak = []
                
                output_lines = result.stdout.lower().split('\n')
                for line in output_lines:
                    if '(enc)' in line:  # Encryption line
                        for cipher in weak_ciphers:
                            if cipher in line and 'warn' in line or 'fail' in line:
                                found_weak.append(cipher)
                
                found_weak = list(set(found_weak))
                
                if found_weak:
                    return "No", f"Weak ciphers found on port {ssh_port}: {', '.join(found_weak)}"
                else:
                    return "Yes", f"Only strong ciphers supported on port {ssh_port}"
            else:
                return "N/A", f"ssh-audit failed to analyze SSH service on port {ssh_port}"
                
        except FileNotFoundError:
            return "N/A", f"ssh-audit tool not available for cipher analysis on port {ssh_port}"
        except subprocess.TimeoutExpired:
            return "Error", f"ssh-audit timed out while checking port {ssh_port}"
        except Exception as e:
            return "Error", f"Cipher check failed on port {ssh_port}: {str(e)}"
            
    except Exception as e:
        return "Error", f"SSH cipher check failed: {str(e)}"


def check_ssh_key_algorithms(ip, domain=None):
    """Check SSH key algorithm strength"""
    try:
        # Check multiple possible SSH ports
        ssh_ports = [22, 2222, 2022]
        ssh_port = None
        
        for port in ssh_ports:
            if quick_port_scan(ip, [port], timeout=2):
                ssh_port = port
                break
        
        if not ssh_port:
            return "N/A", "No SSH service detected on common ports (22, 2222, 2022)"
        
        try:
            result = subprocess.run(['ssh-audit', f'{ip}:{ssh_port}'], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                weak_algorithms = ['ssh-dss', 'ssh-rsa-sha1', 'ecdsa-sha2-nistp256', 'rsa1024']
                found_weak = []
                
                output_lines = result.stdout.lower().split('\n')
                for line in output_lines:
                    if '(key)' in line:  # Key algorithm line
                        for algo in weak_algorithms:
                            if algo in line and ('warn' in line or 'fail' in line):
                                found_weak.append(algo)
                
                found_weak = list(set(found_weak))
                
                if found_weak:
                    return "No", f"Weak key algorithms found on port {ssh_port}: {', '.join(found_weak)}"
                else:
                    return "Yes", f"Only strong key algorithms supported on port {ssh_port}"
            else:
                return "N/A", f"ssh-audit failed to analyze key algorithms on port {ssh_port}"
                
        except FileNotFoundError:
            return "N/A", f"ssh-audit tool not available for key algorithm analysis on port {ssh_port}"
        except subprocess.TimeoutExpired:
            return "Error", f"ssh-audit timed out while checking port {ssh_port}"
        except Exception as e:
            return "Error", f"Key algorithm check failed on port {ssh_port}: {str(e)}"
            
    except Exception as e:
        return "Error", f"SSH key algorithm check failed: {str(e)}"


def check_ssh_mac(ip, domain=None):
    """Check SSH MAC algorithm strength"""
    try:
        # Check multiple possible SSH ports
        ssh_ports = [22, 2222, 2022]
        ssh_port = None
        
        for port in ssh_ports:
            if quick_port_scan(ip, [port], timeout=2):
                ssh_port = port
                break
        
        if not ssh_port:
            return "N/A", "No SSH service detected on common ports (22, 2222, 2022)"
        
        try:
            result = subprocess.run(['ssh-audit', f'{ip}:{ssh_port}'], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                weak_macs = ['hmac-md5', 'hmac-sha1-96', 'umac-64', 'hmac-ripemd160']
                found_weak = []
                
                output_lines = result.stdout.lower().split('\n')
                for line in output_lines:
                    if '(mac)' in line:  # MAC algorithm line
                        for mac in weak_macs:
                            if mac in line and ('warn' in line or 'fail' in line):
                                found_weak.append(mac)
                
                found_weak = list(set(found_weak))
                
                if found_weak:
                    return "No", f"Weak MAC algorithms found on port {ssh_port}: {', '.join(found_weak)}"
                else:
                    return "Yes", f"Only strong MAC algorithms supported on port {ssh_port}"
            else:
                return "N/A", f"ssh-audit failed to analyze MAC algorithms on port {ssh_port}"
                
        except FileNotFoundError:
            return "N/A", f"ssh-audit tool not available for MAC algorithm analysis on port {ssh_port}"
        except subprocess.TimeoutExpired:
            return "Error", f"ssh-audit timed out while checking port {ssh_port}"
        except Exception as e:
            return "Error", f"MAC algorithm check failed on port {ssh_port}: {str(e)}"
            
    except Exception as e:
        return "Error", f"SSH MAC algorithm check failed: {str(e)}"
    
def check_ftp_accessible(ip, domain=None):
    """Check if FTP service is accessible"""
    try:
        if quick_port_scan(ip, [21]):
            # Try to get FTP banner
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((ip, 21))
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                return "Yes", f"FTP service is accessible on port 21: {banner.strip()[:50]}"
            except:
                return "Yes", "FTP service is accessible on port 21"
        return "No", "FTP service is not accessible"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_ftp_version(ip, domain=None):
    """Check if FTP version is visible"""
    try:
        if not quick_port_scan(ip, [21]):
            return "N/A", "FTP port not open"
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, 21))
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()
        
        # Check for version information in banner
        if re.search(r'\d+\.\d+', banner):
            return "No", f"FTP version visible: {banner.strip()[:50]}"
        elif 'FTP' in banner.upper():
            return "Yes", "FTP banner present but version hidden"
        else:
            return "Yes", "FTP version not visible"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_ftp_secure(ip, domain=None):
    """Check if FTP is accessible over secure channel"""
    try:
        ftp_ports = quick_port_scan(ip, [21, 990])
        
        if 990 in ftp_ports:
            return "Yes", "FTPS (secure FTP) is available on port 990"
        elif 21 in ftp_ports:
            # Check if FTP supports AUTH TLS
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((ip, 21))
                sock.recv(1024)  # Get banner
                sock.send(b"AUTH TLS\r\n")
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                
                if '234' in response:  # 234 = AUTH TLS accepted
                    return "Yes", "FTP supports TLS encryption (AUTH TLS)"
                else:
                    return "No", "Only plain FTP available, no secure channel"
            except:
                return "No", "Only plain FTP available"
        else:
            return "N/A", "No FTP service detected"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_ftp_anonymous(ip, domain=None):
    """Check if anonymous FTP upload is allowed"""
    try:
        if not quick_port_scan(ip, [21]):
            return "N/A", "FTP port not open"
        
        # Try anonymous login
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((ip, 21))
            
            # Get banner
            sock.recv(1024)
            
            # Try anonymous login
            sock.send(b"USER anonymous\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if '331' in response:  # Password required
                sock.send(b"PASS anonymous@test.com\r\n")
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if '230' in response:  # Login successful
                    # Check if upload is allowed
                    sock.send(b"STOR testfile\r\n")
                    response = sock.recv(1024).decode('utf-8', errors='ignore')
                    sock.close()
                    
                    if '150' in response or '125' in response:
                        return "No", "Anonymous FTP upload is allowed"
                    elif '550' in response or '553' in response:
                        return "Yes", "Anonymous FTP allowed but upload disabled"
                    else:
                        return "Yes", "Anonymous login allowed but upload appears restricted"
                else:
                    sock.close()
                    return "Yes", "Anonymous FTP login is not allowed"
            else:
                sock.close()
                return "Yes", "Anonymous FTP is not allowed"
        except:
            return "Yes", "Could not verify anonymous FTP (likely disabled)"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_dns_ports(ip, domain=None):
    """Check for open ports other than DNS required ports"""
    try:
        # Quick scan of common ports
        common_ports = list(range(1, 1001))
        open_ports = quick_port_scan(ip, common_ports)
        
        dns_ports = [53]
        non_dns_ports = [p for p in open_ports if p not in dns_ports]
        
        if non_dns_ports:
            return "-", f"Non-DNS ports open: {', '.join(map(str, non_dns_ports[:10]))}"
        elif 53 in open_ports:
            return "-", "Only DNS port (53) is open"
        else:
            return "-", "No ports detected open (including DNS)"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_dns_version(ip, domain=None):
    """Check if DNS version is visible"""
    try:
        if not quick_port_scan(ip, [53]):
            return "N/A", "DNS port not open"
        
        # Try version.bind query
        try:
            result = subprocess.run(['dig', f'@{ip}', 'version.bind', 'txt', 'chaos'], 
                                  capture_output=True, text=True, timeout=10)
            
            if 'ANSWER: 1' in result.stdout:
                # Extract version from answer section
                for line in result.stdout.split('\n'):
                    if 'TXT' in line and 'version.bind' in line:
                        version = line.split('"')[1] if '"' in line else 'Unknown version'
                        return "No", f"DNS version visible: {version}"
            
            return "Yes", "DNS version is not visible"
        except:
            return "Error", "dig command not available or query failed"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_dns_recursion(ip, domain=None):
    """Check if DNS server supports recursion"""
    try:
        if not quick_port_scan(ip, [53]):
            return "N/A", "DNS port not open"
        
        # Test recursion with external domain query
        try:
            result = subprocess.run(['dig', f'@{ip}', 'google.com', 'A', '+short'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.stdout.strip() and re.match(r'^\d+\.\d+\.\d+\.\d+', result.stdout.strip()):
                return "No", "DNS server allows recursion (open resolver)"
            
            # Also check with +norecurse flag to confirm
            result2 = subprocess.run(['dig', f'@{ip}', 'google.com', 'A', '+norecurse'], 
                                   capture_output=True, text=True, timeout=10)
            
            if 'REFUSED' in result2.stdout or 'no servers could be reached' in result2.stdout:
                return "Yes", "DNS recursion is properly restricted"
            
            return "Yes", "DNS recursion appears to be restricted"
        except:
            return "Error", "dig command not available"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_dns_randomization(ip, domain=None):
    """Check DNS port and transaction ID randomization"""
    try:
        if not quick_port_scan(ip, [53]):
            return "N/A", "DNS port not open"
        
        # This is a simplified check - full randomization test requires multiple queries
        return "N/A", "DNS randomization check requires specialized tools (use dns-oarc.net porttest)"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_dnssec(ip, domain=None):
    """Check if DNSSEC is implemented"""
    try:
        if not domain:
            return "N/A", "Domain required for DNSSEC check"
        
        if not quick_port_scan(ip, [53]):
            return "N/A", "DNS port not open"
        
        result = subprocess.run(['dig', f'@{ip}', domain, '+dnssec', '+short'], 
                              capture_output=True, text=True, timeout=10)
        
        # Look for RRSIG records
        if 'RRSIG' in result.stdout:
            return "Yes", "DNSSEC is implemented"
        
        # Try with different query
        result2 = subprocess.run(['dig', f'@{ip}', domain, 'DNSKEY', '+short'], 
                               capture_output=True, text=True, timeout=10)
        
        if result2.stdout.strip():
            return "Yes", "DNSSEC is implemented (DNSKEY found)"
        
        return "No", "DNSSEC is not implemented"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_dnssec_rsa256(ip, domain=None):
    """Check if DNSSEC uses RSA256"""
    try:
        if not domain:
            return "N/A", "Domain required for DNSSEC RSA256 check"
        
        if not quick_port_scan(ip, [53]):
            return "N/A", "DNS port not open"
        
        result = subprocess.run(['dig', f'@{ip}', domain, 'DNSKEY', '+multi'], 
                              capture_output=True, text=True, timeout=10)
        
        if 'DNSKEY' in result.stdout:
            # Algorithm 8 is RSASHA256
            if ' 8 ' in result.stdout:
                return "Yes", "DNSSEC uses RSA256 (Algorithm 8)"
            else:
                # Extract algorithm numbers
                algorithms = re.findall(r'DNSKEY\s+\d+\s+\d+\s+(\d+)', result.stdout)
                if algorithms:
                    return "No", f"DNSSEC uses algorithm(s): {', '.join(set(algorithms))}"
                return "No", "DNSSEC implemented but not using RSA256"
        return "N/A", "DNSSEC not implemented"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_nsec_walking(ip, domain=None):
    """Check if NSEC walking is possible"""
    try:
        if not domain:
            return "N/A", "Domain required for NSEC walking check"
        
        if not quick_port_scan(ip, [53]):
            return "N/A", "DNS port not open"
        
        # Basic check - full NSEC walking test is complex
        result = subprocess.run(['dig', f'@{ip}', f'nonexistent.{domain}', 'A', '+dnssec'], 
                              capture_output=True, text=True, timeout=10)
        
        if 'NSEC3' in result.stdout:
            return "Yes", "NSEC3 is used (NSEC walking prevented)"
        elif 'NSEC' in result.stdout and 'NSEC3' not in result.stdout:
            return "No", "NSEC records found (potential zone walking risk)"
        
        return "N/A", "Cannot determine NSEC status"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_spf_record(ip, domain=None):
    """Check if SPF record exists with -all"""
    try:
        if not domain:
            return "N/A", "Domain required for SPF check"
        
        result = subprocess.run(['dig', 'TXT', domain, '+short'], 
                              capture_output=True, text=True, timeout=10)
        
        spf_records = [line for line in result.stdout.split('\n') if 'v=spf1' in line]
        
        if spf_records:
            spf = spf_records[0]
            if '-all' in spf:
                return "Yes", "SPF record exists with '-all' (hard fail)"
            elif '~all' in spf:
                return "No", "SPF record exists but uses '~all' (soft fail)"
            elif '?all' in spf:
                return "No", "SPF record exists but uses '?all' (neutral)"
            elif '+all' in spf:
                return "No", "SPF record exists but uses '+all' (allows all - insecure)"
            else:
                return "No", "SPF record exists but missing 'all' mechanism"
        return "No", "No SPF record found"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_dmarc_record(ip, domain=None):
    """Check if DMARC record exists"""
    try:
        if not domain:
            return "N/A", "Domain required for DMARC check"
        
        result = subprocess.run(['dig', 'TXT', f'_dmarc.{domain}', '+short'], 
                              capture_output=True, text=True, timeout=10)
        
        if 'v=DMARC1' in result.stdout:
            dmarc = result.stdout.strip()
            if 'p=reject' in dmarc:
                return "Yes", "DMARC record exists with reject policy"
            elif 'p=quarantine' in dmarc:
                return "Yes", "DMARC record exists with quarantine policy"
            elif 'p=none' in dmarc:
                return "No", "DMARC record exists but with 'none' policy (monitoring only)"
            else:
                return "Yes", "DMARC record exists"
        return "No", "No DMARC record found"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_dkim_record(ip, domain=None):
    """Check if DKIM record exists"""
    try:
        if not domain:
            return "N/A", "Domain required for DKIM check"
        
        # Common DKIM selectors
        selectors = ['default', 'google', 'k1', 'k2', 'email', 'mail', 'dkim', 
                    'selector1', 'selector2', 's1', 's2']
        
        for selector in selectors:
            try:
                result = subprocess.run(['dig', 'TXT', f'{selector}._domainkey.{domain}', '+short'], 
                                      capture_output=True, text=True, timeout=5)
                
                if 'v=DKIM1' in result.stdout or 'k=rsa' in result.stdout:
                    return "Yes", f"DKIM record found (selector: {selector})"
            except:
                continue
        
        return "No", "No DKIM record found with common selectors"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_caa_record(ip, domain=None):
    """Check if CAA record exists"""
    try:
        if not domain:
            return "N/A", "Domain required for CAA check"
        
        result = subprocess.run(['dig', 'CAA', domain, '+short'], 
                              capture_output=True, text=True, timeout=10)
        
        if result.stdout.strip() and 'issue' in result.stdout:
            return "Yes", f"CAA record is published: {result.stdout.strip()[:100]}"
        return "No", "No CAA record found"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_zone_transfer(ip, domain=None):
    """Check if zone transfer is allowed"""
    try:
        if not domain:
            return "N/A", "Domain required for zone transfer check"
        
        if not quick_port_scan(ip, [53]):
            return "N/A", "DNS port not open"
        
        result = subprocess.run(['dig', f'@{ip}', domain, 'AXFR'], 
                              capture_output=True, text=True, timeout=15)
        
        # Check if transfer was successful
        if 'Transfer failed' in result.stdout or 'failed' in result.stdout.lower():
            return "Yes", "Zone transfer is properly disabled"
        elif result.stdout.count(f'{domain}.') > 10:  # Multiple records returned
            return "No", "Zone transfer is allowed (security risk)"
        elif 'communications error' in result.stdout.lower():
            return "Yes", "Zone transfer appears to be disabled"
        else:
            return "Yes", "Zone transfer is restricted"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_email_relay(ip, domain=None):
    """Check if email server acts as open relay"""
    try:
        if not quick_port_scan(ip, [25]):
            return "N/A", "SMTP port not open"
        
        # Try using swaks if available
        try:
            result = subprocess.run(['swaks', '--server', ip, '--from', 'test@external.com', 
                                   '--to', 'test@another-external.com', '--quit-after', 'RCPT'], 
                                  capture_output=True, text=True, timeout=30)
            
            if '250' in result.stdout and 'Recipient' in result.stdout:
                return "No", "Server may act as open relay"
            else:
                return "Yes", "Server does not act as open relay"
        except FileNotFoundError:
            # Fallback to socket method
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((ip, 25))
                
                # Get banner
                banner = sock.recv(1024)
                
                # EHLO
                sock.send(b"EHLO test.com\r\n")
                response = sock.recv(1024)
                
                # Try to relay
                sock.send(b"MAIL FROM:<test@external.com>\r\n")
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if '250' in response:
                    sock.send(b"RCPT TO:<test@another-external.com>\r\n")
                    response = sock.recv(1024).decode('utf-8', errors='ignore')
                    sock.close()
                    
                    if '250' in response:
                        return "No", "Server accepts relay (open relay detected)"
                    else:
                        return "Yes", "Server rejects relay attempts"
                else:
                    sock.close()
                    return "Yes", "Server rejects unauthorized senders"
            except:
                return "Yes", "Could not test relay (likely protected)"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_mta_version(ip, domain=None):
    """Check if MTA version is visible"""
    try:
        if not quick_port_scan(ip, [25]):
            return "N/A", "SMTP port not open"
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, 25))
        
        # Get banner
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        
        # Also try EHLO to get more info
        sock.send(b"EHLO test.com\r\n")
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()
        
        # Check for version information
        version_patterns = [
            r'Postfix \d+\.\d+',
            r'Sendmail \d+\.\d+', 
            r'Exim \d+\.\d+',
            r'Exchange Server \d+',
            r'Microsoft ESMTP MAIL Service.*Version: \d+',
            r'qmail \d+\.\d+'
        ]
        
        full_response = banner + response
        for pattern in version_patterns:
            match = re.search(pattern, full_response, re.IGNORECASE)
            if match:
                return "No", f"MTA version visible: {match.group()}"
        
        # Check if any MTA name is visible without version
        mta_names = ['postfix', 'sendmail', 'exim', 'exchange', 'qmail', 'zimbra']
        for mta in mta_names:
            if mta in full_response.lower():
                return "Yes", f"MTA identified as {mta} but version hidden"
        
        return "Yes", "MTA version is not visible"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_mta_old_version(ip, domain=None):
    """Check if MTA is using old/discontinued version"""
    try:
        if not quick_port_scan(ip, [25]):
            return "N/A", "SMTP port not open"
        
        # Get version info first
        status, details = check_mta_version(ip, domain)
        
        if status == "No" and "version visible" in details:
            # Extract version info
            version_str = details.lower()
            
            # Define old versions (simplified - should be updated regularly)
            old_indicators = [
                ('sendmail', ['8.12', '8.13', '8.14']),
                ('postfix', ['2.0', '2.1', '2.2', '2.3', '2.4', '2.5', '2.6', '2.7', '2.8', '2.9']),
                ('exim', ['3.', '4.0', '4.1', '4.2', '4.3', '4.4', '4.5', '4.6']),
                ('exchange', ['2003', '2007', '2010', '2013'])
            ]
            
            for mta, old_versions in old_indicators:
                if mta in version_str:
                    for old_ver in old_versions:
                        if old_ver in version_str:
                            return "No", f"MTA using old version: {details.split(':')[1].strip()}"
            
            return "Yes", "MTA software appears to be current"
        
        return "N/A", "Cannot determine MTA version"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_mta_tls(ip, domain=None):
    """Check if MTA supports TLS"""
    try:
        if not quick_port_scan(ip, [25]):
            return "N/A", "SMTP port not open"
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((ip, 25))
        
        # Get banner
        sock.recv(1024)
        
        # Send EHLO
        sock.send(b"EHLO test.com\r\n")
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()
        
        if 'STARTTLS' in response:
            return "Yes", "MTA supports TLS (STARTTLS available)"
        else:
            return "No", "MTA does not support TLS"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_smtp_auth(ip, domain=None):
    """Check if SMTP AUTH is disabled on MX server"""
    try:
        if not quick_port_scan(ip, [25]):
            return "N/A", "SMTP port not open"
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((ip, 25))
        
        # Get banner
        sock.recv(1024)
        
        # Send EHLO
        sock.send(b"EHLO test.com\r\n")
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()
        
        if 'AUTH' in response and any(auth in response for auth in ['LOGIN', 'PLAIN', 'CRAM']):
            # Extract AUTH methods
            auth_line = [line for line in response.split('\n') if 'AUTH' in line][0]
            return "No", f"SMTP-AUTH is enabled: {auth_line.strip()}"
        else:
            return "Yes", "SMTP-AUTH is disabled"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_user_enumeration(ip, domain=None):
    """Check if user enumeration via VRFY is disabled"""
    try:
        if not quick_port_scan(ip, [25]):
            return "N/A", "SMTP port not open"
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((ip, 25))
        
        # Get banner
        banner = smtp_send_recv(sock, None)
        
        # Send EHLO
        response = smtp_send_recv(sock, "EHLO test.com")
        
        # Try VRFY command
        vrfy_response = smtp_send_recv(sock, "VRFY root")
        sock.close()
        
        if vrfy_response:
            code = vrfy_response[:3]
            if code == "250":
                return "No", "User enumeration possible via VRFY (user confirmed)"
            elif code == "252":
                return "No", "VRFY returns ambiguous response (partial enumeration)"
            elif code in ["502", "500", "503"]:
                return "Yes", f"VRFY command is disabled (code {code})"
            else:
                return "Yes", f"VRFY properly restricted (code {code})"
        else:
            return "Error", "No response to VRFY command"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_domain_spoofing(ip, domain=None):
    """Check if server blocks incoming mail with own domain spoofed"""
    if not domain:
        return "N/A", "Domain required for spoofing check"
    
    try:
        if not quick_port_scan(ip, [25]):
            return "N/A", "SMTP port not open"
        
        # Try using swaks if available
        try:
            result = subprocess.run(['swaks', '--server', ip, '--from', f'spoofed@{domain}', 
                                   '--to', f'legitimate@{domain}', '--quit-after', 'DATA'], 
                                  capture_output=True, text=True, timeout=30)
            
            if '250' in result.stdout and 'accepted' in result.stdout.lower():
                return "No", "Server accepts spoofed sender from own domain"
            else:
                return "Yes", "Server blocks spoofed sender from own domain"
        except FileNotFoundError:
            # Manual test via socket
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((ip, 25))
                
                # Get banner
                smtp_send_recv(sock, None)
                
                # EHLO
                smtp_send_recv(sock, "EHLO external.com")
                
                # Try spoofed sender
                mail_response = smtp_send_recv(sock, f"MAIL FROM:<spoofed@{domain}>")
                
                if '250' in mail_response:
                    rcpt_response = smtp_send_recv(sock, f"RCPT TO:<legitimate@{domain}>")
                    sock.close()
                    
                    if '250' in rcpt_response:
                        return "No", "Server accepts mail with spoofed sender from own domain"
                    else:
                        return "Yes", "Server rejects spoofed domain at RCPT stage"
                else:
                    sock.close()
                    return "Yes", "Server rejects spoofed domain at MAIL FROM stage"
            except:
                return "N/A", "Could not test domain spoofing"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_punny_code_spoofing(ip, domain=None):
    """Check if server blocks punnycode spoofed domains"""
    if not domain:
        return "N/A", "Domain required for punnycode spoofing check"
    
    # This requires actual punnycode domain testing
    return "N/A", "Punnycode spoofing check requires manual testing with IDN domains"

def check_subdomain_spoofing(ip, domain=None):
    """Check if server blocks subdomain spoofing"""
    if not domain:
        return "N/A", "Domain required for subdomain spoofing check"
    
    try:
        if not quick_port_scan(ip, [25]):
            return "N/A", "SMTP port not open"
        
        # Try using swaks if available
        try:
            result = subprocess.run(['swaks', '--server', ip, '--from', f'spoofed@fake.{domain}', 
                                   '--to', f'legitimate@{domain}', '--quit-after', 'DATA'], 
                                  capture_output=True, text=True, timeout=30)
            
            if '250' in result.stdout and 'accepted' in result.stdout.lower():
                return "No", "Server accepts spoofed sender from subdomain"
            else:
                return "Yes", "Server blocks spoofed sender from subdomain"
        except FileNotFoundError:
            return "N/A", "swaks not available for subdomain spoofing test"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_subdomain_punny_spoofing(ip, domain=None):
    """Check subdomain punnycode spoofing"""
    return check_punny_code_spoofing(ip, domain)

def check_subdomain_block(ip, domain=None):
    """Check subdomain spoofing blocking"""
    return check_subdomain_spoofing(ip, domain)

def check_rbl_rejection(ip, domain=None):
    """Check if MTA rejects mails from poor reputation IPs"""
    # This would require testing from a known blacklisted IP
    return "N/A", "RBL rejection check requires testing from blacklisted IPs"

def check_dns_match(ip, domain=None):
    """Check reverse and forward DNS match"""
    try:
        # Reverse DNS lookup
        try:
            import socket
            hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(ip)
            
            # Forward DNS lookup
            try:
                forward_ip = socket.gethostbyname(hostname)
                if forward_ip == ip:
                    return "Yes", f"Forward and reverse DNS match (hostname: {hostname})"
                else:
                    return "No", f"Forward/reverse DNS mismatch: {hostname} resolves to {forward_ip}, not {ip}"
            except:
                return "No", f"Forward DNS lookup failed for {hostname}"
        except:
            return "No", "No reverse DNS (PTR) record found for IP"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_https_required(ip, domain=None):
    """Check if web service runs on HTTPS"""
    try:
        web_ports = quick_port_scan(ip, [80, 443])
        
        if not web_ports:
            return "N/A", "No web service detected"
        
        if 443 in web_ports and 80 not in web_ports:
            return "Yes", "Only HTTPS (port 443) is available"
        elif 443 in web_ports and 80 in web_ports:
            # Check if HTTP redirects to HTTPS
            try:
                response = requests.get(f"http://{ip}", timeout=5, allow_redirects=False)
                if response.status_code in [301, 302, 307, 308]:
                    location = response.headers.get('Location', '')
                    if 'https' in location:
                        return "Yes", "HTTP redirects to HTTPS"
                return "No", "Both HTTP and HTTPS available without forced redirect"
            except:
                return "No", "Both HTTP (80) and HTTPS (443) are available"
        elif 80 in web_ports:
            return "No", "Only HTTP is available, no HTTPS"
        else:
            return "N/A", "No standard web ports open"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_web_version_disclosure(ip, domain=None):
    """Check if web server version is disclosed in headers"""
    try:
        web_ports = quick_port_scan(ip, [80, 443, 8080, 8443])
        if not web_ports:
            return "N/A", "No web service detected"
        
        version_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']
        found_versions = []
        
        for port in web_ports:
            protocol = 'https' if port in [443, 8443] else 'http'
            try:
                response = requests.get(f"{protocol}://{ip}:{port}", timeout=5, verify=False)
                
                for header in version_headers:
                    if header in response.headers:
                        value = response.headers[header]
                        # Check if version number is present
                        if re.search(r'\d+\.\d+', value) or re.search(r'/\d+', value):
                            found_versions.append(f"{header}: {value}")
            except:
                continue
        
        if found_versions:
            return "No", f"Version disclosed: {'; '.join(found_versions[:3])}"
        return "Yes", "Web server version is not disclosed"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_software_version_headers(ip, domain=None):
    """Check if PHP/CMS version is disclosed"""
    try:
        web_ports = quick_port_scan(ip, [80, 443, 8080, 8443])
        if not web_ports:
            return "N/A", "No web service detected"
        
        software_indicators = []
        
        for port in web_ports:
            protocol = 'https' if port in [443, 8443] else 'http'
            try:
                response = requests.get(f"{protocol}://{ip}:{port}", timeout=5, verify=False)
                
                # Check headers
                for header, value in response.headers.items():
                    # PHP version
                    if 'php' in value.lower() and re.search(r'\d+\.\d+', value):
                        software_indicators.append(f"PHP version in {header}: {value}")
                    
                    # CMS indicators
                    cms_patterns = {
                        'wordpress': r'WordPress[\s/]\d+\.\d+',
                        'joomla': r'Joomla[\s/]\d+\.\d+',
                        'drupal': r'Drupal[\s/]\d+',
                        'magento': r'Magento[\s/]\d+'
                    }
                    
                    for cms, pattern in cms_patterns.items():
                        if re.search(pattern, value, re.IGNORECASE):
                            software_indicators.append(f"{cms} version in {header}: {value}")
                
                # Check meta tags in HTML
                if 'text/html' in response.headers.get('Content-Type', ''):
                    generator_match = re.search(r'<meta name="generator" content="([^"]+)"', response.text)
                    if generator_match and re.search(r'\d+\.\d+', generator_match.group(1)):
                        software_indicators.append(f"Generator meta tag: {generator_match.group(1)}")
            except:
                continue
        
        if software_indicators:
            return "No", f"Software versions disclosed: {'; '.join(software_indicators[:3])}"
        return "Yes", "PHP/CMS versions are not disclosed"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_deprecated_ssl(ip, domain=None):
    """Check if deprecated SSL/TLS versions are supported"""
    try:
        if not quick_port_scan(ip, [443]):
            return "N/A", "HTTPS port not open"
        
        # Try using nmap ssl-enum-ciphers script
        try:
            result = subprocess.run(['nmap', '--script', 'ssl-enum-ciphers', '-p', '443', ip], 
                                  capture_output=True, text=True, timeout=60)
            
            deprecated_found = []
            
            # Check for deprecated protocols
            deprecated_protocols = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']
            
            for protocol in deprecated_protocols:
                if protocol in result.stdout and 'cipher preference' in result.stdout:
                    deprecated_found.append(protocol)
            
            if deprecated_found:
                return "No", f"Deprecated protocols supported: {', '.join(deprecated_found)}"
            
            if 'TLSv1.2' in result.stdout or 'TLSv1.3' in result.stdout:
                return "Yes", "Only modern TLS versions supported"
            
            # If nmap script didn't work well, try basic SSL connection test
            return "N/A", "Could not determine SSL/TLS versions"
        except:
            # Fallback check
            return "N/A", "nmap ssl-enum-ciphers not available"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_cms_admin_access(ip, domain=None):
    """Check if CMS admin interfaces are accessible"""
    try:
        web_ports = quick_port_scan(ip, [80, 443, 8080, 8443])
        if not web_ports:
            return "N/A", "No web service detected"
        
        # Common CMS admin paths
        admin_paths = {
            'WordPress': ['/wp-admin/', '/wp-login.php'],
            'Joomla': ['/administrator/'],
            'Drupal': ['/user/login', '/admin', '/user'],
            'Magento': ['/admin', '/index.php/admin'],
            'Tomcat': ['/manager/html', '/host-manager/html'],
            'phpMyAdmin': ['/phpmyadmin/', '/pma/', '/phpMyAdmin/'],
            'cPanel': ['/cpanel', '/whm'],
            'Plesk': ['/plesk/']
        }
        
        accessible_interfaces = []
        
        for port in web_ports[:2]:  # Check only first 2 ports to save time
            protocol = 'https' if port in [443, 8443] else 'http'
            
            for cms, paths in admin_paths.items():
                for path in paths:
                    try:
                        url = f"{protocol}://{ip}:{port}{path}"
                        response = requests.get(url, timeout=3, verify=False, allow_redirects=True)
                        
                        if response.status_code in [200, 401, 403]:
                            # Check if it's actually a login page
                            login_indicators = ['login', 'password', 'username', 'sign in', 'log in', 
                                              'authentication', 'admin', 'dashboard']
                            
                            if any(indicator in response.text.lower() for indicator in login_indicators):
                                accessible_interfaces.append(f"{cms} at {path} (port {port})")
                                break  # Found for this CMS, skip other paths
                            elif response.status_code in [401, 403]:
                                accessible_interfaces.append(f"{cms} at {path} (protected, port {port})")
                                break
                    except:
                        continue
        
        if accessible_interfaces:
            return "No", f"Admin interfaces accessible: {'; '.join(accessible_interfaces[:3])}"
        return "Yes", "No CMS admin interfaces found accessible"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_web_vulnerabilities(ip, domain=None):
    """Basic web vulnerability check placeholder"""
    return "N/A", "Web vulnerability scanning requires specialized tools (OWASP ZAP, Burp Suite, etc.)"

def check_cdn_vulnerabilities(ip, domain=None):
    """Check vulnerabilities for CDN-hosted sites"""
    return "N/A", "CDN vulnerability scanning requires specialized configuration and tools"

# Function mapping
CHECK_FUNCTIONS = {
    "check_open_ports": check_open_ports,
    "check_management_ports": check_management_ports,
    "check_login_visibility": check_login_visibility,
    "check_services": check_services,
    "check_version_disclosure": check_version_disclosure,
    "check_ssh_ports": check_ssh_ports,
    "check_ssh_version": check_ssh_version,
    "check_ssh_protocol": check_ssh_protocol,
    "check_ssh_ciphers": check_ssh_ciphers,
    "check_ssh_key_algorithms": check_ssh_key_algorithms,
    "check_ssh_mac": check_ssh_mac,
    "check_ftp_ports": check_ftp_ports,
    "check_ftp_accessible": check_ftp_accessible,
    "check_ftp_version": check_ftp_version,
    "check_ftp_secure": check_ftp_secure,
    "check_ftp_anonymous": check_ftp_anonymous,
    "check_dns_ports": check_dns_ports,
    "check_dns_version": check_dns_version,
    "check_dns_recursion": check_dns_recursion,
    "check_dns_randomization": check_dns_randomization,
    "check_dnssec": check_dnssec,
    "check_dnssec_rsa256": check_dnssec_rsa256,
    "check_nsec_walking": check_nsec_walking,
    "check_spf_record": check_spf_record,
    "check_dmarc_record": check_dmarc_record,
    "check_dkim_record": check_dkim_record,
    "check_caa_record": check_caa_record,
    "check_zone_transfer": check_zone_transfer,
    "check_email_relay": check_email_relay,
    "check_mta_version": check_mta_version,
    "check_mta_old_version": check_mta_old_version,
    "check_mta_tls": check_mta_tls,
    "check_smtp_auth": check_smtp_auth,
    "check_user_enumeration": check_user_enumeration,
    "check_domain_spoofing": check_domain_spoofing,
    "check_punny_code_spoofing": check_punny_code_spoofing,
    "check_subdomain_spoofing": check_subdomain_spoofing,
    "check_subdomain_punny_spoofing": check_subdomain_punny_spoofing,
    "check_subdomain_block": check_subdomain_block,
    "check_rbl_rejection": check_rbl_rejection,
    "check_dns_match": check_dns_match,
    "check_web_ports": check_web_ports,
    "check_https_required": check_https_required,
    "check_web_version_disclosure": check_web_version_disclosure,
    "check_software_version_headers": check_software_version_headers,
    "check_deprecated_ssl": check_deprecated_ssl,
    "check_cms_admin_access": check_cms_admin_access,
    "check_web_vulnerabilities": check_web_vulnerabilities,
    "check_cdn_vulnerabilities": check_cdn_vulnerabilities
}

# Save results to database
def save_to_db(results):
    """Save results to database with comprehensive error handling"""
    if not results:
        st.warning("No results to save")
        return 0
    
    conn = None
    try:
        conn = sqlite3.connect('compliance_results.db', timeout=30)
        c = conn.cursor()
        
        # Ensure table exists with all required columns
        c.execute('''CREATE TABLE IF NOT EXISTS compliance_results
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      scan_date TIMESTAMP,
                      service_type TEXT,
                      ip_address TEXT,
                      domain TEXT,
                      sr_no INTEGER,
                      parameter TEXT,
                      compliance_status TEXT,
                      threat_level TEXT,
                      remarks TEXT,
                      command_used TEXT,
                      hostname TEXT,
                      target_type TEXT)''')
        
        # Check if table needs column updates
        cursor = c.execute("PRAGMA table_info(compliance_results)")
        columns = [column[1] for column in cursor.fetchall()]
        
        # Add missing columns if needed
        missing_columns = []
        required_columns = ['hostname', 'target_type', 'domain']
        
        for col in required_columns:
            if col not in columns:
                missing_columns.append(col)
        
        for col in missing_columns:
            try:
                c.execute(f'ALTER TABLE compliance_results ADD COLUMN {col} TEXT')
                st.info(f"Added missing column: {col}")
            except sqlite3.OperationalError:
                pass  # Column might already exist
        
        conn.commit()
        
        # Convert results to proper format
        if isinstance(results, pd.DataFrame):
            results_list = results.to_dict('records')
        elif isinstance(results, list) and results:
            if isinstance(results[0], dict):
                results_list = results
            else:
                # Try to convert other formats
                try:
                    results_list = [dict(r) for r in results]
                except:
                    st.error("Cannot convert results to proper format for database saving")
                    return 0
        else:
            st.error("Invalid results format for database saving")
            return 0
        
        saved_count = 0
        failed_count = 0
        
        for result in results_list:
            try:
                # Handle datetime conversion
                scan_date = result.get('scan_date')
                if scan_date:
                    if hasattr(scan_date, 'strftime'):
                        scan_date_str = scan_date.strftime('%Y-%m-%d %H:%M:%S')
                    elif isinstance(scan_date, str):
                        scan_date_str = scan_date
                    else:
                        scan_date_str = str(scan_date)
                else:
                    scan_date_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                
                # Clean and validate data
                def clean_value(value, default=''):
                    if value is None:
                        return default
                    if isinstance(value, (int, float)):
                        return value
                    return str(value).strip()
                
                # Prepare data with proper validation
                data = (
                    scan_date_str,
                    clean_value(result.get('service_type')),
                    clean_value(result.get('ip_address')),
                    clean_value(result.get('domain')),
                    int(result.get('sr_no', 0)) if result.get('sr_no') and str(result.get('sr_no')).isdigit() else 0,
                    clean_value(result.get('parameter')),
                    clean_value(result.get('compliance_status')),
                    clean_value(result.get('threat_level')),
                    clean_value(result.get('remarks')),
                    clean_value(result.get('command_used')),
                    clean_value(result.get('hostname')),
                    clean_value(result.get('target_type'))
                )
                
                # Validate required fields
                if not data[1] or not data[2]:  # service_type and ip_address are required
                    st.warning(f"Skipping record with missing required fields: {data}")
                    failed_count += 1
                    continue
                
                c.execute('''INSERT INTO compliance_results 
                             (scan_date, service_type, ip_address, domain, sr_no, parameter, 
                              compliance_status, threat_level, remarks, command_used, hostname, target_type)
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', data)
                
                saved_count += 1
                
            except Exception as e:
                st.warning(f"Error saving individual result: {e}")
                failed_count += 1
                continue
        
        conn.commit()
        
        if saved_count > 0:
            st.success(f"✅ Successfully saved {saved_count} records to database")
        
        if failed_count > 0:
            st.warning(f"⚠️ Failed to save {failed_count} records")
        
        return saved_count
        
    except sqlite3.Error as e:
        st.error(f"Database error: {e}")
        if conn:
            conn.rollback()
        return 0
    except Exception as e:
        st.error(f"Unexpected error saving to database: {e}")
        return 0
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass
# Generate PDF report
# def generate_pdf_report(results, scan_info):
#     buffer = io.BytesIO()
#     doc = SimpleDocTemplate(buffer, pagesize=A4)
#     elements = []
    
#     # Styles
#     styles = getSampleStyleSheet()
#     title_style = ParagraphStyle(
#         'CustomTitle',
#         parent=styles['Heading1'],
#         fontSize=24,
#         textColor=colors.HexColor('#1f4788'),
#         spaceAfter=30,
#         alignment=1
#     )
    
#     # Title
#     elements.append(Paragraph("Security Compliance Report", title_style))
#     elements.append(Spacer(1, 20))
    
#     # Scan Information
#     info_data = [
#         ['Scan Date:', scan_info['scan_date']],
#         ['Service Type:', scan_info['service_type']],
#         ['IP Address:', scan_info['ip_address']]
#     ]
    
#     if scan_info.get('domain'):
#         info_data.append(['Domain:', scan_info['domain']])
    
#     info_table = Table(info_data, colWidths=[2*inch, 4*inch])
#     info_table.setStyle(TableStyle([
#         ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
#         ('FONTSIZE', (0, 0), (-1, -1), 12),
#         ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#1f4788')),
#     ]))
#     elements.append(info_table)
#     elements.append(Spacer(1, 30))
    
#     # Summary Statistics
#     total_checks = len(results)
#     compliant = len([r for r in results if r['compliance_status'] == 'Yes'])
#     non_compliant = len([r for r in results if r['compliance_status'] == 'No'])
#     errors = len([r for r in results if r['compliance_status'] == 'Error'])
#     na_checks = len([r for r in results if r['compliance_status'] == 'N/A'])
    
#     summary_data = [
#         ['Total Checks:', str(total_checks)],
#         ['Compliant:', f"{compliant} ({compliant/total_checks*100:.1f}%)"],
#         ['Non-Compliant:', f"{non_compliant} ({non_compliant/total_checks*100:.1f}%)"],
#         ['Not Applicable:', f"{na_checks}"],
#         ['Errors:', str(errors)]
#     ]
    
#     summary_table = Table(summary_data, colWidths=[2*inch, 2*inch])
#     summary_table.setStyle(TableStyle([
#         ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
#         ('FONTSIZE', (0, 0), (-1, -1), 10),
#         ('GRID', (0, 0), (-1, -1), 1, colors.grey),
#         ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
#     ]))
#     elements.append(summary_table)
#     elements.append(Spacer(1, 30))
    
#     # High priority issues
#     high_priority = [r for r in results if r['threat_level'] == 'High' and r['compliance_status'] == 'No']
#     if high_priority:
#         elements.append(Paragraph("High Priority Issues", styles['Heading2']))
#         elements.append(Spacer(1, 10))
        
#         high_data = [['Parameter', 'Remarks']]
#         for issue in high_priority:
#             high_data.append([
#                 Paragraph(issue['parameter'][:60] + '...' if len(issue['parameter']) > 60 else issue['parameter'], styles['Normal']),
#                 Paragraph(issue['remarks'][:60] + '...' if len(issue['remarks']) > 60 else issue['remarks'], styles['Normal'])
#             ])
        
#         high_table = Table(high_data, colWidths=[4*inch, 3.3*inch])
#         high_table.setStyle(TableStyle([
#             ('BACKGROUND', (0, 0), (-1, 0), colors.red),
#             ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
#             ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
#             ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
#             ('FONTSIZE', (0, 0), (-1, 0), 11),
#             ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
#             ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
#             ('GRID', (0, 0), (-1, -1), 1, colors.black),
#         ]))
#         elements.append(high_table)
#         elements.append(Spacer(1, 20))
    
#     # All results
#     elements.append(Paragraph("Detailed Compliance Check Results", styles['Heading2']))
#     elements.append(Spacer(1, 10))
    
#     # Group by threat level
#     for threat in ['High', 'Medium', 'Low', 'Info']:
#         threat_results = [r for r in results if r['threat_level'] == threat]
#         if threat_results:
#             elements.append(Paragraph(f"{threat} Priority Checks", styles['Heading3']))
            
#             data = [['Parameter', 'Status', 'Remarks']]
#             for result in threat_results:
#                 # Color code status
#                 if result['compliance_status'] == 'No':
#                     status = Paragraph(f"<font color='red'><b>{result['compliance_status']}</b></font>", styles['Normal'])
#                 elif result['compliance_status'] == 'Yes':
#                     status = Paragraph(f"<font color='green'><b>{result['compliance_status']}</b></font>", styles['Normal'])
#                 else:
#                     status = Paragraph(result['compliance_status'], styles['Normal'])
                
#                 data.append([
#                     Paragraph(result['parameter'][:50] + '...' if len(result['parameter']) > 50 else result['parameter'], styles['Normal']),
#                     status,
#                     Paragraph(result['remarks'][:40] + '...' if len(result['remarks']) > 40 else result['remarks'], styles['Normal'])
#                 ])
            
#             table = Table(data, colWidths=[3.5*inch, 0.8*inch, 3*inch])
#             table.setStyle(TableStyle([
#                 ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
#                 ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
#                 ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
#                 ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
#                 ('FONTSIZE', (0, 0), (-1, 0), 10),
#                 ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
#                 ('BACKGROUND', (0, 1), (-1, -1), colors.white),
#                 ('GRID', (0, 0), (-1, -1), 1, colors.black),
#                 ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
#                 ('FONTSIZE', (0, 1), (-1, -1), 9),
#                 ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f0f0')]),
#             ]))
#             elements.append(table)
#             elements.append(Spacer(1, 15))
    
#     # Build PDF
#     doc.build(elements)
#     buffer.seek(0)
#     return buffer

# Generate PDF report




# Fixed PDF generation function
def generate_pdf_report(results, scan_info):
    """Generate PDF report with proper error handling"""
    try:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        elements = []
        
        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1f4788'),
            spaceAfter=30,
            alignment=1
        )
        
        # Title
        elements.append(Paragraph("Security Compliance Report", title_style))
        elements.append(Spacer(1, 20))
        
        # Scan Information - handle missing keys gracefully
        info_data = [
            ['Scan Date:', str(scan_info.get('scan_date', 'Unknown'))],
            ['Service Type:', str(scan_info.get('service_type', 'Unknown'))],
            ['IP Address:', str(scan_info.get('ip_address', 'Unknown'))]
        ]
        
        if scan_info.get('domain') and scan_info['domain'] != 'N/A':
            info_data.append(['Domain:', str(scan_info['domain'])])
        
        if scan_info.get('hostname') and scan_info['hostname'] != 'manual':
            info_data.append(['Hostname:', str(scan_info['hostname'])])
        
        info_table = Table(info_data, colWidths=[2*inch, 4*inch])
        info_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#1f4788')),
        ]))
        elements.append(info_table)
        elements.append(Spacer(1, 30))
        
        # Convert results to proper format if needed
        if results and isinstance(results, list) and len(results) > 0:
            if isinstance(results[0], dict):
                results_list = results
            else:
                # Handle pandas DataFrame or other formats
                try:
                    if hasattr(results, 'to_dict'):
                        results_list = results.to_dict('records')
                    else:
                        results_list = list(results)
                except:
                    results_list = []
        else:
            results_list = []
        
        if not results_list:
            elements.append(Paragraph("No compliance check results available", styles['Normal']))
            doc.build(elements)
            buffer.seek(0)
            return buffer
        
        # Summary Statistics
        total_checks = len(results_list)
        compliant = len([r for r in results_list if str(r.get('compliance_status', '')).strip() == 'Yes'])
        non_compliant = len([r for r in results_list if str(r.get('compliance_status', '')).strip() == 'No'])
        errors = len([r for r in results_list if str(r.get('compliance_status', '')).strip() == 'Error'])
        na_checks = len([r for r in results_list if str(r.get('compliance_status', '')).strip() == 'N/A'])
        info_checks = len([r for r in results_list if str(r.get('compliance_status', '')).strip() == '-'])
        
        if total_checks > 0:
            summary_data = [
                ['Total Checks:', str(total_checks)],
                ['Compliant:', f"{compliant} ({compliant/total_checks*100:.1f}%)"],
                ['Non-Compliant:', f"{non_compliant} ({non_compliant/total_checks*100:.1f}%)"],
                ['Not Applicable:', str(na_checks)],
                ['Informational:', str(info_checks)],
                ['Errors:', str(errors)]
            ]
            
            summary_table = Table(summary_data, colWidths=[2*inch, 2*inch])
            summary_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ]))
            elements.append(summary_table)
            elements.append(Spacer(1, 30))
        
        # High priority issues
        high_priority = [r for r in results_list if str(r.get('threat_level', '')).strip() == 'High' and str(r.get('compliance_status', '')).strip() == 'No']
        if high_priority:
            elements.append(Paragraph("High Priority Issues", styles['Heading2']))
            elements.append(Spacer(1, 10))
            
            high_data = [['Sr. No.', 'Parameter', 'Remarks']]
            # Sort high priority issues by sr_no
            high_priority_sorted = sorted(high_priority, key=lambda x: int(x.get('sr_no', 999)))
            
            for issue in high_priority_sorted:
                sr_no = str(issue.get('sr_no', ''))
                parameter = str(issue.get('parameter', ''))
                remarks = str(issue.get('remarks', ''))
                
                # Limit text length to prevent table overflow
                if len(parameter) > 80:
                    parameter = parameter[:80] + '...'
                if len(remarks) > 80:
                    remarks = remarks[:80] + '...'
                
                high_data.append([
                    sr_no,
                    Paragraph(parameter, styles['Normal']),
                    Paragraph(remarks, styles['Normal'])
                ])
            
            high_table = Table(high_data, colWidths=[0.8*inch, 3.5*inch, 3*inch])
            high_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.red),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            elements.append(high_table)
            elements.append(Spacer(1, 20))
        
        # Main compliance results table
        elements.append(Paragraph("Detailed Compliance Check Results", styles['Heading2']))
        elements.append(Spacer(1, 10))
        
        # Create table data
        data = [['Sr. No.', 'Parameters', 'Compliance (Yes/No)', 'Threat Level', 'Remarks']]
        
        # Sort results by sr_no
        sorted_results = sorted(results_list, key=lambda x: int(x.get('sr_no', 999)))
        
        for result in sorted_results:
            sr_no = str(result.get('sr_no', ''))
            parameter = str(result.get('parameter', ''))
            compliance_status = str(result.get('compliance_status', ''))
            threat_level = str(result.get('threat_level', ''))
            remarks = str(result.get('remarks', ''))
            
            # Limit text length to prevent table overflow
            if len(parameter) > 60:
                parameter = parameter[:60] + '...'
            if len(remarks) > 60:
                remarks = remarks[:60] + '...'
            
            # Color code compliance status
            if compliance_status == 'No':
                status = Paragraph(f"<font color='red'><b>{compliance_status}</b></font>", styles['Normal'])
            elif compliance_status == 'Yes':
                status = Paragraph(f"<font color='green'><b>{compliance_status}</b></font>", styles['Normal'])
            elif compliance_status == '-':
                status = Paragraph(f"<font color='blue'><b>-</b></font>", styles['Normal'])
            else:
                status = Paragraph(compliance_status, styles['Normal'])
            
            data.append([
                sr_no,
                Paragraph(parameter, styles['Normal']),
                status,
                threat_level,
                Paragraph(remarks, styles['Normal'])
            ])
        
        # Create table with proper column widths
        table = Table(data, colWidths=[0.6*inch, 3.2*inch, 1.2*inch, 0.8*inch, 2.5*inch])
        table.setStyle(TableStyle([
            # Header row styling
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            
            # Data rows styling
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f8f8')]),
            
            # Center align specific columns
            ('ALIGN', (0, 0), (0, -1), 'CENTER'),  # Sr. No. column
            ('ALIGN', (2, 0), (2, -1), 'CENTER'),  # Compliance column
            ('ALIGN', (3, 0), (3, -1), 'CENTER'),  # Threat Level column
        ]))
        elements.append(table)
        
        # Build PDF
        doc.build(elements)
        buffer.seek(0)
        return buffer
        
    except Exception as e:
        print(f"PDF Generation Error: {str(e)}")
        # Create a simple error PDF if main generation fails
        try:
            buffer = io.BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=A4)
            styles = getSampleStyleSheet()
            
            elements = [
                Paragraph("Error Generating Report", styles['Title']),
                Spacer(1, 20),
                Paragraph(f"An error occurred while generating the PDF report: {str(e)}", styles['Normal']),
                Spacer(1, 20),
                Paragraph("Please check the scan results and try again.", styles['Normal'])
            ]
            
            doc.build(elements)
            buffer.seek(0)
            return buffer
        except Exception as inner_e:
            print(f"Error PDF Generation also failed: {str(inner_e)}")
            # If even error PDF fails, return empty buffer
            empty_buffer = io.BytesIO()
            empty_buffer.write(b"PDF generation failed")
            empty_buffer.seek(0)
            return empty_buffer
        


# ============== ENHANCED UI FUNCTIONS ==============

def render_smart_input_section(service_type):
    """Render smart input section based on service type"""
    
    st.subheader("🎯 Target Configuration")
    
    if service_type == "DNS Server":
        st.info("💡 **Smart Discovery**: Enter a domain name and we'll automatically find its DNS servers!")
        
        col1, col2 = st.columns([2, 1])
        with col1:
            target_input = st.text_input(
                "Domain Name",
                placeholder="example.com",
                help="Enter the domain to discover its authoritative DNS servers",
                key="dns_input"
            )
        with col2:
            st.markdown("<br>", unsafe_allow_html=True)
            manual_mode = st.checkbox("Manual IP Entry", help="Check to enter IP addresses manually")
        
        if manual_mode:
            manual_input = st.text_input(
                "Manual IP Addresses",
                placeholder="8.8.8.8, 1.1.1.1",
                help="Enter DNS server IPs separated by commas",
                key="dns_manual"
            )
            return manual_input, "manual"
        
        return target_input, "auto"
    
    elif service_type == "Email Service":
        st.info("💡 **Smart Discovery**: Enter a domain name and we'll automatically find its mail servers!")
        
        col1, col2 = st.columns([2, 1])
        with col1:
            target_input = st.text_input(
                "Domain Name",
                placeholder="example.com",
                help="Enter the domain to discover its mail servers (MX records)",
                key="email_input"
            )
        with col2:
            st.markdown("<br>", unsafe_allow_html=True)
            manual_mode = st.checkbox("Manual IP Entry", help="Check to enter mail server IPs manually")
        
        if manual_mode:
            manual_input = st.text_input(
                "Manual IP Addresses",
                placeholder="192.168.1.10, 192.168.1.11",
                help="Enter mail server IPs separated by commas",
                key="email_manual"
            )
            return manual_input, "manual"
        
        return target_input, "auto"
    
    elif service_type == "Web Application":
        st.info("💡 **Smart Discovery**: Enter a domain name or IP address - we'll handle both!")
        
        target_input = st.text_input(
            "Domain or IP Address",
            placeholder="example.com or 192.168.1.1",
            help="Enter domain name (we'll resolve to IPs) or IP addresses",
            key="web_input"
        )
        return target_input, "smart"
    
    else:
        # Traditional IP input for SSH, FTP, UTM services
        st.info(f"📍 **{service_type}**: Requires specific IP addresses")
        
        target_input = st.text_input(
            "IP Address",
            placeholder="192.168.1.1",
            help="Enter the IP address to scan",
            key="traditional_input"
        )
        return target_input, "traditional"

def display_discovery_results(discovery_result):
    """Display auto-discovery results and allow user selection"""
    
    st.subheader("🔍 Discovery Results")
    
    if discovery_result['errors']:
        st.warning("⚠️ Discovery Issues:")
        for error in discovery_result['errors']:
            st.text(f"• {error}")
    
    discovered = discovery_result['discovered_targets']
    manual = discovery_result['manual_targets']
    
    selected_targets = []
    
    if discovered:
        st.success(f"✅ **Auto-discovered {len(discovered)} target(s):**")
        
        for i, target in enumerate(discovered):
            col1, col2, col3 = st.columns([1, 3, 2])
            
            with col1:
                selected = st.checkbox(
                    "Select", 
                    value=True, 
                    key=f"discovered_{i}",
                    help="Include this target in the scan"
                )
            
            with col2:
                if target.get('hostname') and target['hostname'] != 'manual':
                    st.text(f"📍 {target['hostname']}")
                    st.text(f"🌐 {target['ip']}")
                else:
                    st.text(f"🌐 {target['ip']}")
            
            with col3:
                if 'priority' in target:
                    st.text(f"Priority: {target['priority']}")
                if 'ports_detected' in target and target['ports_detected']:
                    st.text(f"Ports: {', '.join(map(str, target['ports_detected']))}")
                st.caption(f"Type: {target['type']}")
            
            if selected:
                selected_targets.append(target)
    
    if manual:
        st.info(f"📝 **Manual targets ({len(manual)}):**")
        
        for i, target in enumerate(manual):
            col1, col2, col3 = st.columns([1, 3, 2])
            
            with col1:
                selected = st.checkbox(
                    "Select", 
                    value=True, 
                    key=f"manual_{i}",
                    help="Include this target in the scan"
                )
            
            with col2:
                st.text(f"🌐 {target['ip']}")
            
            with col3:
                st.caption(f"Source: {target['source']}")
            
            if selected:
                selected_targets.append(target)
    
    if not discovered and not manual:
        st.error("❌ No targets discovered or provided")
        return []
    
    if not selected_targets:
        st.warning("⚠️ No targets selected for scanning")
        return []
    
    st.success(f"✅ **{len(selected_targets)} target(s) selected for scanning**")
    return selected_targets

def enhanced_compliance_check_page():
    """Enhanced compliance check page with auto-discovery"""
    
    st.header("🔍 Enhanced Compliance Check")
    
    # Service selection
    service_type = st.selectbox(
        "Select Service Type",
        options=list(COMPLIANCE_TYPES.keys()),
        help="Choose the type of service to scan",
        key="service_selector"
    )
    
    # Smart input section
    target_input, input_mode = render_smart_input_section(service_type)
    
    # Domain input for services that need it (only show if not auto-discovery mode)
    domain_input = None
    if service_type in ["DNS Server", "Email Service"] and input_mode != "auto":
        domain_input = st.text_input(
            "Domain (Optional)",
            placeholder="example.com",
            help="Required for some DNS record checks and email spoofing tests",
            key="domain_optional"
        )
    
    # Advanced options
    with st.expander("⚙️ Advanced Options"):
        col1, col2 = st.columns(2)
        with col1:
            timeout = st.slider("Connection Timeout (seconds)", 1, 10, 5)
        with col2:
            max_threads = st.slider("Max Parallel Connections", 10, 100, 50)
    
    st.markdown("---")
    
    # Discovery and scanning section
    if st.button("🔍 Discover Targets", type="secondary", use_container_width=True):
        if target_input:
            with st.spinner("🔍 Discovering targets..."):
                if input_mode in ["auto", "smart"]:
                    discovery_result = auto_discover_targets(service_type, target_input)
                    st.session_state['discovery_result'] = discovery_result
                    st.session_state['target_input'] = target_input
                    st.session_state['service_type'] = service_type
                    
                    if discovery_result['discovered_targets'] or discovery_result['manual_targets']:
                        st.rerun()
                    else:
                        st.error("❌ No targets could be discovered. Please check your input and try again.")
                
                else:  # manual or traditional
                    parsed_input = smart_input_parser(target_input)
                    
                    if parsed_input['type'] == 'invalid':
                        st.error("❌ Invalid input format. Please enter valid IP addresses.")
                    else:
                        manual_targets = []
                        for item in parsed_input['items']:
                            if item['type'] == 'ip':
                                manual_targets.append({
                                    'hostname': 'manual',
                                    'ip': item['value'],
                                    'type': 'manual',
                                    'source': 'user_input'
                                })
                        
                        discovery_result = {
                            'service_type': service_type,
                            'discovered_targets': [],
                            'manual_targets': manual_targets,
                            'errors': []
                        }
                        
                        st.session_state['discovery_result'] = discovery_result
                        st.session_state['target_input'] = target_input
                        st.session_state['service_type'] = service_type
                        st.session_state['domain_input'] = domain_input
                        
                        st.rerun()
        else:
            st.warning("⚠️ Please enter a domain name or IP address")
    
    # Display discovery results if available
    if 'discovery_result' in st.session_state:
        discovery_result = st.session_state['discovery_result']
        selected_targets = display_discovery_results(discovery_result)
        
        if selected_targets:
            st.markdown("---")
            
            # Extract domain from discovery
            discovered_domain = None
            if service_type in ["DNS Server", "Email Service"]:
                if discovery_result.get('discovered_targets'):
                    for target in discovery_result['discovered_targets']:
                        if 'hostname' in target and target['hostname'] != 'manual':
                            hostname = target['hostname']
                            parts = hostname.split('.')
                            if len(parts) >= 2:
                                discovered_domain = '.'.join(parts[-2:])
                                break
                
                if not discovered_domain and st.session_state.get('domain_input'):
                    discovered_domain = st.session_state['domain_input']
                
                if not discovered_domain and st.session_state.get('target_input'):
                    parsed = smart_input_parser(st.session_state['target_input'])
                    for item in parsed['items']:
                        if item['type'] == 'domain':
                            discovered_domain = item['value']
                            break
            
            # Run compliance check button
            if st.button("🚀 Run Compliance Check", type="primary", use_container_width=True):
                run_enhanced_compliance_scan(selected_targets, service_type, discovered_domain)

# def run_enhanced_compliance_scan(selected_targets, service_type, domain=None):
#     """Run compliance scan on selected targets"""
    
#     results = []
#     scan_date = datetime.datetime.now()
    
#     st.subheader("🔄 Running Compliance Checks")
    
#     total_targets = len(selected_targets)
#     overall_progress = st.progress(0)
#     overall_status = st.empty()
    
#     for target_idx, target in enumerate(selected_targets):
#         ip_address = target['ip']
#         hostname = target.get('hostname', 'Unknown')
        
#         overall_progress.progress((target_idx) / total_targets)
#         overall_status.text(f"Scanning target {target_idx + 1} of {total_targets}: {hostname} ({ip_address})")
        
#         with st.expander(f"🎯 Target: {hostname} ({ip_address})", expanded=True):
#             params = COMPLIANCE_TYPES[service_type]["parameters"]
#             total_params = len(params)
            
#             target_progress = st.progress(0)
#             target_status = st.empty()
#             results_placeholder = st.empty()
#             current_results = []
            
#             for param_idx, param_info in enumerate(params):
#                 progress = (param_idx + 1) / total_params
#                 target_progress.progress(progress)
#                 target_status.text(f"Checking: {param_info['parameter'][:60]}...")
                
#                 check_func_name = param_info["check_function"]
#                 if check_func_name in CHECK_FUNCTIONS:
#                     try:
#                         if domain:
#                             compliance_status, remarks = CHECK_FUNCTIONS[check_func_name](ip_address, domain)
#                         else:
#                             compliance_status, remarks = CHECK_FUNCTIONS[check_func_name](ip_address)
                        
#                         result = {
#                             'scan_date': scan_date,
#                             'service_type': service_type,
#                             'ip_address': ip_address,
#                             'sr_no': param_info['sr_no'],
#                             'parameter': param_info['parameter'],
#                             'compliance_status': compliance_status,
#                             'threat_level': param_info.get('threat_level', 'Info'),
#                             'remarks': remarks,
#                             'command_used': param_info.get('command', '').format(ip=ip_address, domain=domain or ''),
#                             'hostname': hostname,
#                             'target_type': target.get('type', 'unknown')
#                         }
                        
#                         if domain:
#                             result['domain'] = domain
                        
#                         current_results.append(result)
#                         results.append(result)
                        
#                         df = pd.DataFrame(current_results)
#                         df = df.sort_values('sr_no')
#                         results_placeholder.dataframe(df[['sr_no', 'parameter', 'compliance_status', 'threat_level', 'remarks']], use_container_width=True)
                        
#                     except Exception as e:
#                         st.error(f"Error running check '{param_info['parameter']}': {str(e)}")
#                         continue
                
#                 time.sleep(0.05)
            
#             target_progress.empty()
#             target_status.empty()
            
#             if current_results:
#                 compliant_count = len([r for r in current_results if r['compliance_status'] == 'Yes'])
#                 total_checks = len(current_results)
                
#                 col1, col2, col3 = st.columns(3)
#                 with col1:
#                     st.metric("Total Checks", total_checks)
#                 with col2:
#                     st.metric("Compliant", f"{compliant_count} ({compliant_count/total_checks*100:.1f}%)")
#                 with col3:
#                     non_compliant = len([r for r in current_results if r['compliance_status'] == 'No'])
#                     st.metric("Issues Found", non_compliant)
                
#                 if st.button(f"📄 Generate Report for {hostname}", key=f"report_{target_idx}"):
#                     pdf_buffer = generate_pdf_report(current_results, {
#                         'service_type': service_type,
#                         'ip_address': ip_address,
#                         'domain': domain or 'N/A',
#                         'scan_date': scan_date.strftime('%Y-%m-%d %H:%M:%S'),
#                         'hostname': hostname
#                     })
                    
#                     filename = f"compliance_report_{hostname}_{ip_address}_{scan_date.strftime('%Y%m%d_%H%M%S')}.pdf"
#                     st.download_button(
#                         label=f"📥 Download {hostname} Report",
#                         data=pdf_buffer,
#                         file_name=filename,
#                         mime="application/pdf",
#                         key=f"download_{target_idx}"
#                     )
    
#     overall_progress.progress(1.0)
#     overall_status.text("✅ All scans completed!")
    
#     if results:
#         st.markdown("---")
#         st.subheader("📊 Scan Summary")
        
#         total_results = len(results)
#         total_compliant = len([r for r in results if r['compliance_status'] == 'Yes'])
#         total_non_compliant = len([r for r in results if r['compliance_status'] == 'No'])
#         high_priority_issues = len([r for r in results if r['threat_level'] == 'High' and r['compliance_status'] == 'No'])
        
#         col1, col2, col3, col4 = st.columns(4)
#         with col1:
#             st.metric("Total Checks", total_results)
#         with col2:
#             st.metric("Compliant", f"{total_compliant} ({total_compliant/total_results*100:.1f}%)")
#         with col3:
#             st.metric("Issues Found", total_non_compliant)
#         with col4:
#             st.metric("High Priority Issues", high_priority_issues)
        
#         col1, col2 = st.columns(2)
        
#         with col1:
#             if st.button("📄 Generate Combined Report", type="secondary"):
#                 pdf_buffer = generate_pdf_report(results, {
#                     'service_type': service_type,
#                     'ip_address': f"Multiple targets ({len(selected_targets)})",
#                     'domain': domain or 'Multiple/N/A',
#                     'scan_date': scan_date.strftime('%Y-%m-%d %H:%M:%S')
#                 })
                
#                 st.download_button(
#                     label="📥 Download Combined Report",
#                     data=pdf_buffer,
#                     file_name=f"combined_compliance_report_{scan_date.strftime('%Y%m%d_%H%M%S')}.pdf",
#                     mime="application/pdf"
#                 )
        
#         with col2:
#             if st.button("💾 Save to Database", type="secondary"):
#                 try:
#                     save_to_db(results)
#                     st.success(f"✅ {len(results)} scan results saved to database")
#                 except Exception as e:
#                     st.error(f"❌ Error saving to database: {str(e)}")
        
#         if st.button("🔄 Start New Scan", type="secondary"):
#             for key in ['discovery_result', 'target_input', 'service_type', 'domain_input']:
#                 if key in st.session_state:
#                     del st.session_state[key]
#             st.rerun()


def run_enhanced_compliance_scan(selected_targets, service_type, domain=None):
    """Run compliance scan on selected targets with fixed PDF generation and database saving"""
    
    results = []
    scan_date = datetime.datetime.now()
    
    st.subheader("🔄 Running Compliance Checks")
    
    total_targets = len(selected_targets)
    overall_progress = st.progress(0)
    overall_status = st.empty()
    
    for target_idx, target in enumerate(selected_targets):
        ip_address = target['ip']
        hostname = target.get('hostname', 'Unknown')
        
        overall_progress.progress((target_idx) / total_targets)
        overall_status.text(f"Scanning target {target_idx + 1} of {total_targets}: {hostname} ({ip_address})")
        
        with st.expander(f"🎯 Target: {hostname} ({ip_address})", expanded=True):
            params = COMPLIANCE_TYPES[service_type]["parameters"]
            total_params = len(params)
            
            target_progress = st.progress(0)
            target_status = st.empty()
            results_placeholder = st.empty()
            current_results = []
            
            for param_idx, param_info in enumerate(params):
                progress = (param_idx + 1) / total_params
                target_progress.progress(progress)
                target_status.text(f"Checking: {param_info['parameter'][:60]}...")
                
                check_func_name = param_info["check_function"]
                if check_func_name in CHECK_FUNCTIONS:
                    try:
                        if domain:
                            compliance_status, remarks = CHECK_FUNCTIONS[check_func_name](ip_address, domain)
                        else:
                            compliance_status, remarks = CHECK_FUNCTIONS[check_func_name](ip_address)
                        
                        # Ensure all values are strings and handle None values
                        result = {
                            'scan_date': scan_date,
                            'service_type': str(service_type),
                            'ip_address': str(ip_address),
                            'sr_no': int(param_info.get('sr_no', 0)),
                            'parameter': str(param_info.get('parameter', '')),
                            'compliance_status': str(compliance_status) if compliance_status else 'Error',
                            'threat_level': str(param_info.get('threat_level', 'Info')),
                            'remarks': str(remarks) if remarks else 'No remarks available',
                            'command_used': str(param_info.get('command', '')).format(
                                ip=ip_address, 
                                domain=domain or ''
                            ),
                            'hostname': str(hostname),
                            'target_type': str(target.get('type', 'unknown')),
                            'domain': str(domain) if domain else ''
                        }
                        
                        current_results.append(result)
                        results.append(result)
                        
                        # Update display
                        try:
                            df = pd.DataFrame(current_results)
                            df = df.sort_values('sr_no')
                            display_df = df[['sr_no', 'parameter', 'compliance_status', 'threat_level', 'remarks']].copy()
                            results_placeholder.dataframe(display_df, use_container_width=True)
                        except Exception as display_error:
                            st.error(f"Display error: {display_error}")
                        
                    except Exception as e:
                        st.error(f"Error running check '{param_info['parameter']}': {str(e)}")
                        
                        # Add error result
                        error_result = {
                            'scan_date': scan_date,
                            'service_type': str(service_type),
                            'ip_address': str(ip_address),
                            'sr_no': int(param_info.get('sr_no', 0)),
                            'parameter': str(param_info.get('parameter', '')),
                            'compliance_status': 'Error',
                            'threat_level': str(param_info.get('threat_level', 'Info')),
                            'remarks': f'Check failed: {str(e)}',
                            'command_used': str(param_info.get('command', '')),
                            'hostname': str(hostname),
                            'target_type': str(target.get('type', 'unknown')),
                            'domain': str(domain) if domain else ''
                        }
                        
                        current_results.append(error_result)
                        results.append(error_result)
                        continue
                
                time.sleep(0.05)
            
            target_progress.empty()
            target_status.empty()
            
            if current_results:
                compliant_count = len([r for r in current_results if r['compliance_status'] == 'Yes'])
                total_checks = len(current_results)
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Total Checks", total_checks)
                with col2:
                    st.metric("Compliant", f"{compliant_count} ({compliant_count/total_checks*100:.1f}%)")
                with col3:
                    non_compliant = len([r for r in current_results if r['compliance_status'] == 'No'])
                    st.metric("Issues Found", non_compliant)
                
                if st.button(f"📄 Generate Report for {hostname}", key=f"report_{target_idx}"):
                    try:
                        with st.spinner("Generating PDF report..."):
                            pdf_buffer = generate_pdf_report(current_results, {
                                'service_type': service_type,
                                'ip_address': ip_address,
                                'domain': domain or 'N/A',
                                'scan_date': scan_date.strftime('%Y-%m-%d %H:%M:%S'),
                                'hostname': hostname
                            })
                            
                            if pdf_buffer and pdf_buffer.getvalue():
                                filename = f"compliance_report_{hostname}_{ip_address}_{scan_date.strftime('%Y%m%d_%H%M%S')}.pdf"
                                st.download_button(
                                    label=f"📥 Download {hostname} Report",
                                    data=pdf_buffer.getvalue(),
                                    file_name=filename,
                                    mime="application/pdf",
                                    key=f"download_{target_idx}"
                                )
                                st.success("✅ PDF report generated successfully!")
                            else:
                                st.error("❌ Failed to generate PDF report")
                    except Exception as pdf_error:
                        st.error(f"PDF generation failed: {pdf_error}")
    
    overall_progress.progress(1.0)
    overall_status.text("✅ All scans completed!")
    
    if results:
        st.markdown("---")
        st.subheader("📊 Scan Summary")
        
        total_results = len(results)
        total_compliant = len([r for r in results if r['compliance_status'] == 'Yes'])
        total_non_compliant = len([r for r in results if r['compliance_status'] == 'No'])
        high_priority_issues = len([r for r in results if r['threat_level'] == 'High' and r['compliance_status'] == 'No'])
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Checks", total_results)
        with col2:
            st.metric("Compliant", f"{total_compliant} ({total_compliant/total_results*100:.1f}%)")
        with col3:
            st.metric("Issues Found", total_non_compliant)
        with col4:
            st.metric("High Priority Issues", high_priority_issues)
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("📄 Generate Combined Report", type="secondary"):
                try:
                    with st.spinner("Generating combined PDF report..."):
                        pdf_buffer = generate_pdf_report(results, {
                            'service_type': service_type,
                            'ip_address': f"Multiple targets ({len(selected_targets)})",
                            'domain': domain or 'Multiple/N/A',
                            'scan_date': scan_date.strftime('%Y-%m-%d %H:%M:%S')
                        })
                        
                        if pdf_buffer and pdf_buffer.getvalue():
                            st.download_button(
                                label="📥 Download Combined Report",
                                data=pdf_buffer.getvalue(),
                                file_name=f"combined_compliance_report_{scan_date.strftime('%Y%m%d_%H%M%S')}.pdf",
                                mime="application/pdf",
                                key="combined_download"
                            )
                            st.success("✅ Combined PDF report generated successfully!")
                        else:
                            st.error("❌ Failed to generate combined PDF report")
                except Exception as pdf_error:
                    st.error(f"Combined PDF generation failed: {pdf_error}")
        
        with col2:
            if st.button("💾 Save to Database", type="secondary"):
                try:
                    with st.spinner("Saving results to database..."):
                        saved_count = save_to_db(results)
                        if saved_count > 0:
                            st.success(f"✅ {saved_count} scan results saved to database")
                        else:
                            st.error("❌ No results were saved to database")
                except Exception as db_error:
                    st.error(f"❌ Error saving to database: {str(db_error)}")
        
        if st.button("🔄 Start New Scan", type="secondary"):
            for key in ['discovery_result', 'target_input', 'service_type', 'domain_input']:
                if key in st.session_state:
                    del st.session_state[key]
            st.rerun()


# Streamlit UI
def main():
    st.set_page_config(page_title="Security Compliance Automation", layout="wide", page_icon="🔒")
    
    # Initialize database
    init_db()
    
    # Custom CSS
    st.markdown("""
    <style>
    .main {
        padding: 0rem 1rem;
    }
    .stButton > button {
        width: 100%;
    }
    div[data-testid="metric-container"] {
        background-color: rgba(28, 131, 225, 0.1);
        border: 1px solid rgba(28, 131, 225, 0.1);
        padding: 5% 5% 5% 10%;
        border-radius: 5px;
        color: rgb(30, 103, 119);
        overflow-wrap: break-word;
    }
    </style>
    """, unsafe_allow_html=True)
    
    st.title("🔒 Security Compliance Automation Tool")
    st.markdown("---")
    
    # Sidebar
    with st.sidebar:
        st.header("Navigation")
        page = st.radio("Select Page", ["🔍 Compliance Check", "📊 Dashboard", "📄 Reports"])
        
        st.markdown("---")
        st.markdown("### Quick Info")
        st.info("""
        **Enhanced Service Types:**
        - 🌐 DNS Server (Auto-discover name servers)
        - 📧 Email Service (Auto-discover mail servers)  
        - 🔗 Web Application (Domain or IP support)
        - 🔑 SSH Service (IP required)
        - 📁 FTP Service (IP required)
        - 🔧 UTM/Switch/Router (IP required)
        """)
        
        st.markdown("### Auto-Discovery Features")
        st.success("✅ **Smart Discovery**")
        st.text("• DNS: Find authoritative servers")
        st.text("• Email: Discover MX servers") 
        st.text("• Web: Resolve domains to IPs")
        
        st.markdown("### Status Legend")
        st.success("**Yes** - Compliant")
        st.error("**No** - Non-compliant")
        st.warning("**N/A** - Not applicable")
        st.info("**-** - Informational")

    if page == "🔍 Compliance Check":
        enhanced_compliance_check_page()  # NEW: Enhanced UI with auto-discovery
        
    elif page == "📊 Dashboard":
        st.header("Compliance Dashboard")
        
        # Get data from database
        try:
            conn = sqlite3.connect('compliance_results.db')
            df = pd.read_sql_query("""
                SELECT service_type, ip_address, parameter, compliance_status, threat_level, scan_date 
                FROM compliance_results 
                ORDER BY scan_date DESC
                LIMIT 1000
            """, conn)
            conn.close()
            
            if not df.empty:
                # Summary metrics
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Total Scans", len(df['scan_date'].unique()))
                with col2:
                    st.metric("Unique IPs", df['ip_address'].nunique())
                with col3:
                    st.metric("Services Monitored", df['service_type'].nunique())
                
                # Recent scans
                st.subheader("Recent Scans")
                st.dataframe(df.head(10))
                
                # Compliance by service type
                st.subheader("Compliance by Service Type")
                service_compliance = df.groupby('service_type')['compliance_status'].value_counts().unstack().fillna(0)
                st.bar_chart(service_compliance)
                
                # Threat level distribution
                st.subheader("Threat Level Distribution")
                threat_dist = df['threat_level'].value_counts()
                st.bar_chart(threat_dist)
                
            else:
                st.info("No scan results found. Run a compliance check first.")
                
        except Exception as e:
            st.error(f"Error loading dashboard data: {str(e)}")
    
    elif page == "📄 Reports":
        st.header("Generate Custom Reports")
        
        # Get unique values for filters from database
        try:
            conn = sqlite3.connect('compliance_results.db')
            
            # Get unique scan combinations (grouped scans)
            scan_combinations_query = """
                SELECT DISTINCT 
                    service_type, 
                    ip_address, 
                    domain,
                    DATE(scan_date) as scan_date_only,
                    MIN(scan_date) as first_scan_time,
                    MAX(scan_date) as last_scan_time,
                    COUNT(*) as parameter_count
                FROM compliance_results 
                GROUP BY service_type, ip_address, COALESCE(domain, ''), DATE(scan_date)
                ORDER BY first_scan_time DESC
            """
            scan_combinations_df = pd.read_sql_query(scan_combinations_query, conn)
            
            # Get filter options
            all_service_types = pd.read_sql_query("SELECT DISTINCT service_type FROM compliance_results", conn)['service_type'].tolist()
            all_ips = pd.read_sql_query("SELECT DISTINCT ip_address FROM compliance_results", conn)['ip_address'].tolist()
            all_domains = pd.read_sql_query("SELECT DISTINCT domain FROM compliance_results WHERE domain IS NOT NULL AND domain != ''", conn)['domain'].tolist()
            
            conn.close()
            
        except Exception as e:
            st.error(f"Error loading data: {str(e)}")
            scan_combinations_df = pd.DataFrame()
            all_service_types = []
            all_ips = []
            all_domains = []
        
        if not scan_combinations_df.empty:
            # Filter Options Section
            st.subheader("🔍 Filter Options")
            
            # Create filter columns
            col1, col2, col3 = st.columns(3)
            
            with col1:
                # Date range selector
                st.markdown("**Date Range**")
                date_filter_type = st.radio(
                    "Select date range",
                    ["Last 7 days", "Last 30 days", "Last 90 days", "Custom range"],
                    horizontal=True
                )
                
                if date_filter_type == "Custom range":
                    start_date = st.date_input("Start Date", value=datetime.datetime.now() - datetime.timedelta(days=30))
                    end_date = st.date_input("End Date", value=datetime.datetime.now())
                else:
                    days_map = {"Last 7 days": 7, "Last 30 days": 30, "Last 90 days": 90}
                    days_back = days_map[date_filter_type]
                    start_date = datetime.datetime.now() - datetime.timedelta(days=days_back)
                    end_date = datetime.datetime.now()
            
            with col2:
                st.markdown("**Service & Infrastructure Filters**")
                service_filter = st.multiselect(
                    "Filter by Service Type",
                    options=all_service_types,
                    default=[],
                    help="Select one or more service types"
                )
                
                ip_filter = st.multiselect(
                    "Filter by IP Address",
                    options=all_ips,
                    default=[],
                    help="Select specific IP addresses"
                )
            
            with col3:
                st.markdown("**Additional Filters**")
                domain_filter = st.multiselect(
                    "Filter by Domain",
                    options=all_domains,
                    default=[],
                    help="Filter by specific domains (DNS/Email services)"
                )
                
                compliance_filter = st.multiselect(
                    "Filter by Compliance Status",
                    options=["Yes", "No", "N/A", "-", "Error"],
                    default=[],
                    help="Show only specific compliance statuses"
                )
            
            # Threat level filter
            threat_filter = st.multiselect(
                "Filter by Threat Level",
                options=["High", "Medium", "Low", "Info"],
                default=[],
                help="Filter by threat/priority level"
            )
            
            st.markdown("---")
            
            # Apply filters to get grouped scans
            filtered_combinations = scan_combinations_df.copy()
            
            # Apply date filter - convert to datetime if not already
            if 'scan_date_only' in filtered_combinations.columns:
                filtered_combinations['scan_date_only'] = pd.to_datetime(filtered_combinations['scan_date_only'])
                start_date_ts = pd.Timestamp(start_date)
                end_date_ts = pd.Timestamp(end_date)
                
                filtered_combinations = filtered_combinations[
                    (filtered_combinations['scan_date_only'] >= start_date_ts) &
                    (filtered_combinations['scan_date_only'] <= end_date_ts)
                ]
            
            # Apply other filters
            if service_filter:
                filtered_combinations = filtered_combinations[filtered_combinations['service_type'].isin(service_filter)]
            if ip_filter:
                filtered_combinations = filtered_combinations[filtered_combinations['ip_address'].isin(ip_filter)]
            if domain_filter:
                filtered_combinations = filtered_combinations[filtered_combinations['domain'].isin(domain_filter)]
            
            # Display Available Scans
            st.subheader("📋 Available Scans")
            
            if not filtered_combinations.empty:
                # Format the display dataframe
                display_df = filtered_combinations.copy()
                display_df['scan_date_only'] = pd.to_datetime(display_df['scan_date_only']).dt.strftime('%Y-%m-%d')
                display_df['first_scan_time'] = pd.to_datetime(display_df['first_scan_time']).dt.strftime('%Y-%m-%d %H:%M:%S')
                display_df = display_df.rename(columns={
                    'service_type': 'Service Type',
                    'ip_address': 'IP Address',
                    'domain': 'Domain',
                    'scan_date_only': 'Scan Date',
                    'parameter_count': 'Parameters Checked',
                    'first_scan_time': 'Scan Time'
                })
                
                # Display with selection
                st.dataframe(
                    display_df[['Service Type', 'IP Address', 'Domain', 'Scan Date', 'Parameters Checked', 'Scan Time']],
                    use_container_width=True
                )
                
                st.markdown("---")
                
                # Individual Scan Report Generation
                st.subheader("📄 Generate Individual Scan Reports")
                
                # Create selection options for individual scans
                scan_options = []
                for _, row in filtered_combinations.iterrows():
                    domain_text = f" | {row['domain']}" if pd.notna(row['domain']) and row['domain'] != '' else ""
                    scan_date_display = pd.to_datetime(row['scan_date_only']).strftime('%Y-%m-%d')
                    option_text = f"{row['service_type']} | {row['ip_address']}{domain_text} | {scan_date_display}"
                    scan_options.append((option_text, row))
                
                if scan_options:
                    selected_scan_text = st.selectbox(
                        "Select a specific scan to generate report:",
                        options=[opt[0] for opt in scan_options],
                        help="Choose a specific scan combination to download its complete report"
                    )
                    
                    # Find selected scan data
                    selected_scan = None
                    for opt_text, row_data in scan_options:
                        if opt_text == selected_scan_text:
                            selected_scan = row_data
                            break
                    
                    if selected_scan is not None and st.button("📥 Generate Individual Scan Report", type="primary"):
                        try:
                            # Get detailed results for the selected scan
                            conn = sqlite3.connect('compliance_results.db')
                            
                            # Convert scan_date to string format for SQL query
                            scan_date_str = pd.to_datetime(selected_scan['scan_date_only']).strftime('%Y-%m-%d')
                            
                            detailed_query = """
                                SELECT * FROM compliance_results 
                                WHERE service_type = ? AND ip_address = ? AND DATE(scan_date) = ?
                            """
                            params = [selected_scan['service_type'], selected_scan['ip_address'], scan_date_str]
                            
                            if pd.notna(selected_scan['domain']) and selected_scan['domain'] != '':
                                detailed_query += " AND domain = ?"
                                params.append(selected_scan['domain'])
                            
                            detailed_query += " ORDER BY sr_no"
                            
                            detailed_df = pd.read_sql_query(detailed_query, conn, params=params)
                            conn.close()
                            
                            if not detailed_df.empty:
                                # Apply additional filters if specified
                                if compliance_filter:
                                    detailed_df = detailed_df[detailed_df['compliance_status'].isin(compliance_filter)]
                                if threat_filter:
                                    detailed_df = detailed_df[detailed_df['threat_level'].isin(threat_filter)]
                                
                                if not detailed_df.empty:
                                    # Generate PDF report
                                    pdf_buffer = generate_pdf_report(detailed_df.to_dict('records'), {
                                        'service_type': selected_scan['service_type'],
                                        'ip_address': selected_scan['ip_address'],
                                        'domain': selected_scan['domain'] if pd.notna(selected_scan['domain']) else 'N/A',
                                        'scan_date': pd.to_datetime(selected_scan['first_scan_time']).strftime('%Y-%m-%d %H:%M:%S')
                                    })
                                    
                                    # Create filename
                                    domain_part = f"_{selected_scan['domain']}" if pd.notna(selected_scan['domain']) and selected_scan['domain'] != '' else ""
                                    scan_date_str = pd.to_datetime(selected_scan['scan_date_only']).strftime('%Y%m%d')
                                    filename = f"compliance_report_{selected_scan['service_type'].replace('/', '_')}_{selected_scan['ip_address']}{domain_part}_{scan_date_str}.pdf"
                                    
                                    st.download_button(
                                        label="📥 Download Individual Scan PDF Report",
                                        data=pdf_buffer,
                                        file_name=filename,
                                        mime="application/pdf"
                                    )
                                    
                                    # Show summary
                                    total_checks = len(detailed_df)
                                    compliant = len(detailed_df[detailed_df['compliance_status'] == 'Yes'])
                                    non_compliant = len(detailed_df[detailed_df['compliance_status'] == 'No'])
                                    
                                    col1, col2, col3 = st.columns(3)
                                    with col1:
                                        st.metric("Total Checks", total_checks)
                                    with col2:
                                        st.metric("Compliant", f"{compliant} ({compliant/total_checks*100:.1f}%)")
                                    with col3:
                                        st.metric("Non-Compliant", f"{non_compliant} ({non_compliant/total_checks*100:.1f}%)")
                                else:
                                    st.warning("No results match the selected filters for this scan.")
                            else:
                                st.error("No detailed results found for the selected scan.")
                                
                        except Exception as e:
                            st.error(f"Error generating individual report: {str(e)}")
            
            else:
                st.info("No scans found matching the selected filters.")
        
        else:
            st.info("No scan results found. Run a compliance check first.")

if __name__ == "__main__":
    main()