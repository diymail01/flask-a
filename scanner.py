import sqlite3
import subprocess
import socket
import datetime
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
import pandas as pd

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

# Input validation functions
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

# Auto-discovery functions
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

# Check functions implementation
def check_open_ports(ip, domain=None):
    """List open ports using quick scan of top ports"""
    try:
        # Quick scan of most common ports
        top_ports = list(range(1, 1001))  # Top 1000 ports
        additional_ports = [3306, 3389, 5432, 5900, 8080, 8443, 10000, 27017]
        all_ports = list(set(top_ports + additional_ports))
        
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

# Alias functions for different services
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

# Add missing function aliases
def check_ssh_ports(ip, domain=None):
    """Check SSH ports - alias for check_open_ports"""
    return check_open_ports(ip, domain)

def check_ftp_ports(ip, domain=None):
    """Check FTP ports - alias for check_open_ports"""
    return check_open_ports(ip, domain)

def check_web_ports(ip, domain=None):
    """Check web ports - alias for check_open_ports"""
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

# Add placeholder functions for missing checks
def check_ssh_version(ip, domain=None):
    """Check if SSH version is visible"""
    try:
        if not quick_port_scan(ip, [22]):
            return "N/A", "SSH port not open"
        return "N/A", "SSH version check not implemented"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_ssh_protocol(ip, domain=None):
    """Check if SSH protocol version 1 is supported"""
    try:
        if not quick_port_scan(ip, [22]):
            return "N/A", "SSH port not open"
        return "N/A", "SSH protocol check not implemented"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_ssh_ciphers(ip, domain=None):
    """Check SSH cipher strength"""
    try:
        if not quick_port_scan(ip, [22]):
            return "N/A", "SSH port not open"
        return "N/A", "SSH cipher check not implemented"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_ssh_key_algorithms(ip, domain=None):
    """Check SSH key algorithm strength"""
    try:
        if not quick_port_scan(ip, [22]):
            return "N/A", "SSH port not open"
        return "N/A", "SSH key algorithm check not implemented"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_ssh_mac(ip, domain=None):
    """Check SSH MAC algorithm strength"""
    try:
        if not quick_port_scan(ip, [22]):
            return "N/A", "SSH port not open"
        return "N/A", "SSH MAC algorithm check not implemented"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_ftp_accessible(ip, domain=None):
    """Check if FTP service is accessible"""
    try:
        if quick_port_scan(ip, [21]):
            return "Yes", "FTP service is accessible on port 21"
        return "No", "FTP service is not accessible"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_ftp_version(ip, domain=None):
    """Check if FTP version is visible"""
    try:
        if not quick_port_scan(ip, [21]):
            return "N/A", "FTP port not open"
        return "N/A", "FTP version check not implemented"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_ftp_secure(ip, domain=None):
    """Check if FTP is accessible over secure channel"""
    try:
        ftp_ports = quick_port_scan(ip, [21, 990])
        if 990 in ftp_ports:
            return "Yes", "FTPS (secure FTP) is available on port 990"
        elif 21 in ftp_ports:
            return "No", "Only plain FTP available, no secure channel"
        else:
            return "N/A", "No FTP service detected"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_ftp_anonymous(ip, domain=None):
    """Check if anonymous FTP upload is allowed"""
    try:
        if not quick_port_scan(ip, [21]):
            return "N/A", "FTP port not open"
        return "N/A", "FTP anonymous check not implemented"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

# Helper: Detect if IP/hostname is a public DNS provider
PUBLIC_DNS_PROVIDERS = [
    '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9', '149.112.112.112',
    '208.67.222.222', '208.67.220.220', '64.6.64.6', '64.6.65.6',
    'cloudflare-dns.com', 'google-public-dns-a.google.com', 'google-public-dns-b.google.com',
    'opendns.com', 'quad9.net', 'verisign.com', 'comodo.com', 'norton.com', 'level3.com'
]
def is_public_dns_provider(ip=None, domain=None, hostname=None):
    # Check by IP, domain, or hostname
    if ip:
        for provider_ip in PUBLIC_DNS_PROVIDERS:
            if provider_ip == ip:
                return True
    if domain:
        for provider in PUBLIC_DNS_PROVIDERS:
            if provider in domain:
                return True
    if hostname:
        for provider in PUBLIC_DNS_PROVIDERS:
            if provider in hostname:
                return True
    return False

def check_dns_ports(ip, domain=None, hostname=None):
    try:
        if is_public_dns_provider(ip=ip, domain=domain, hostname=hostname):
            return "N/A", "Public DNS provider (DNS port not testable from public internet)"
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

def check_dns_version(ip, domain=None, hostname=None):
    try:
        if is_public_dns_provider(ip=ip, domain=domain, hostname=hostname):
            return "N/A", "Public DNS provider (DNS port not testable from public internet)"
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

def check_dns_recursion(ip, domain=None, hostname=None):
    try:
        if is_public_dns_provider(ip=ip, domain=domain, hostname=hostname):
            return "N/A", "Public DNS provider (DNS port not testable from public internet)"
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

def check_dns_randomization(ip, domain=None, hostname=None):
    try:
        if is_public_dns_provider(ip=ip, domain=domain, hostname=hostname):
            return "N/A", "Public DNS provider (DNS port not testable from public internet)"
        # This is a simplified check - full randomization test requires multiple queries
        return "N/A", "DNS randomization check requires specialized tools (use dns-oarc.net porttest)"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_dnssec(ip, domain=None, hostname=None):
    try:
        if is_public_dns_provider(ip=ip, domain=domain, hostname=hostname):
            return "N/A", "Public DNS provider (DNS port not testable from public internet)"
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

def check_dnssec_rsa256(ip, domain=None, hostname=None):
    try:
        if is_public_dns_provider(ip=ip, domain=domain, hostname=hostname):
            return "N/A", "Public DNS provider (DNS port not testable from public internet)"
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
                return "No", "SPF record exists but missing 'all' mechanism"
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

# Helper: Detect if IP/hostname is a public mail provider
PUBLIC_MAIL_PROVIDERS = [
    'gmail.com', 'google.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'yandex.com', 'zoho.com',
    'protonmail.com', 'icloud.com', 'aol.com', 'mail.com', 'gmx.com', 'qq.com', '163.com', '126.com'
]
def is_public_mail_provider(ip=None, domain=None, hostname=None):
    # Check by domain or hostname
    if domain:
        for provider in PUBLIC_MAIL_PROVIDERS:
            if provider in domain:
                return True
    if hostname:
        for provider in PUBLIC_MAIL_PROVIDERS:
            if provider in hostname:
                return True
    # Optionally, check by IP (skip for now, as public IP ranges are large)
    return False

def check_email_relay(ip, domain=None, hostname=None):
    """Check if email server acts as open relay"""
    try:
        if is_public_mail_provider(ip=ip, domain=domain, hostname=hostname):
            return "N/A", "Public mail provider (SMTP port not testable from public internet)"
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

def reliable_smtp_port_check(ip):
    # Try with 5s timeout, retry once if needed
    for _ in range(2):
        open_ports = quick_port_scan(ip, [25], timeout=5)
        if open_ports:
            return True
    return False

def check_mta_version(ip, domain=None, hostname=None):
    """Check if MTA version is visible"""
    try:
        if is_public_mail_provider(ip=ip, domain=domain, hostname=hostname):
            return "N/A", "Public mail provider (SMTP port not testable from public internet)"
        if not reliable_smtp_port_check(ip):
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
            r'Postfix \\d+\.\\d+',
            r'Sendmail \\d+\.\\d+', 
            r'Exim \\d+\.\\d+',
            r'Exchange Server \\d+',
            r'Microsoft ESMTP MAIL Service.*Version: \\d+',
            r'qmail \\d+\.\\d+'
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

def check_mta_old_version(ip, domain=None, hostname=None):
    """Check if MTA is using old/discontinued version"""
    try:
        if is_public_mail_provider(ip=ip, domain=domain, hostname=hostname):
            return "N/A", "Public mail provider (SMTP port not testable from public internet)"
        if not quick_port_scan(ip, [25]):
            return "N/A", "SMTP port not open"
        
        # Get version info first
        status, details = check_mta_version(ip, domain, hostname)
        
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

def check_mta_tls(ip, domain=None, hostname=None):
    """Check if MTA supports TLS"""
    try:
        if is_public_mail_provider(ip=ip, domain=domain, hostname=hostname):
            return "N/A", "Public mail provider (SMTP port not testable from public internet)"
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

def check_smtp_auth(ip, domain=None, hostname=None):
    """Check if SMTP AUTH is disabled on MX server"""
    try:
        if is_public_mail_provider(ip=ip, domain=domain, hostname=hostname):
            return "N/A", "Public mail provider (SMTP port not testable from public internet)"
        if not reliable_smtp_port_check(ip):
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

def check_user_enumeration(ip, domain=None, hostname=None):
    """Check if user enumeration via VRFY is disabled"""
    try:
        if is_public_mail_provider(ip=ip, domain=domain, hostname=hostname):
            return "N/A", "Public mail provider (SMTP port not testable from public internet)"
        if not reliable_smtp_port_check(ip):
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
                return "Yes", f"VRFY properly restricted (code {code})"
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
        if not reliable_smtp_port_check(ip):
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
                
                for header, value in response.headers.items():
                    if 'php' in value.lower() and re.search(r'\d+\.\d+', value):
                        software_indicators.append(f"PHP version in {header}: {value}")
                    
                    cms_patterns = {
                        'wordpress': r'WordPress[\s/]\d+\.\d+',
                        'joomla': r'Joomla[\s/]\d+\.\d+',
                        'drupal': r'Drupal[\s/]\d+',
                        'magento': r'Magento[\s/]\d+'
                    }
                    
                    for cms, pattern in cms_patterns.items():
                        if re.search(pattern, value, re.IGNORECASE):
                            software_indicators.append(f"{cms} version in {header}: {value}")
                
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
        return "N/A", "Deprecated SSL check not implemented"
    except Exception as e:
        return "Error", f"Failed to check: {str(e)}"

def check_cms_admin_access(ip, domain=None):
    """Check if CMS admin interfaces are accessible"""
    try:
        web_ports = quick_port_scan(ip, [80, 443, 8080, 8443])
        if not web_ports:
            return "N/A", "No web service detected"
        
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
        
        for port in web_ports[:2]:
            protocol = 'https' if port in [443, 8443] else 'http'
            
            for cms, paths in admin_paths.items():
                for path in paths:
                    try:
                        url = f"{protocol}://{ip}:{port}{path}"
                        response = requests.get(url, timeout=3, verify=False, allow_redirects=True)
                        
                        if response.status_code in [200, 401, 403]:
                            login_indicators = ['login', 'password', 'username', 'sign in', 'log in', 
                                              'authentication', 'admin', 'dashboard']
                            
                            if any(indicator in response.text.lower() for indicator in login_indicators):
                                accessible_interfaces.append(f"{cms} at {path} (port {port})")
                                break
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
                    return 0
        else:
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
                    failed_count += 1
                    continue
                
                c.execute('''INSERT INTO compliance_results 
                             (scan_date, service_type, ip_address, domain, sr_no, parameter, 
                              compliance_status, threat_level, remarks, command_used, hostname, target_type)
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', data)
                
                saved_count += 1
                
            except Exception as e:
                failed_count += 1
                continue
        
        conn.commit()
        return saved_count
        
    except sqlite3.Error as e:
        if conn:
            conn.rollback()
        return 0
    except Exception as e:
        return 0
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass 