from flask import Flask, render_template, request, redirect, url_for, send_file, flash, session, jsonify, Response
import os
from scanner import init_db, auto_discover_targets, CHECK_FUNCTIONS, save_to_db
import datetime
import sqlite3
import pandas as pd
from demo import generate_pdf_report

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Initialize database on startup
init_db()

# Compliance types from the original app
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

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/compliance', methods=['GET', 'POST'])
def compliance():
    if request.method == 'POST':
        service_type = request.form.get('service_type')
        target_input = request.form.get('target_input')
        domain_input = request.form.get('domain_input', '')
        
        if not service_type or not target_input:
            flash('Please select a service type and enter target input.', 'error')
            return redirect(url_for('compliance'))
        
        # Store form data in session for processing
        session['compliance_data'] = {
            'service_type': service_type,
            'target_input': target_input,
            'domain_input': domain_input
        }
        
        return redirect(url_for('compliance_results'))
    
    return render_template('compliance.html', compliance_types=COMPLIANCE_TYPES.keys())

@app.route('/compliance/results')
def compliance_results():
    if 'compliance_data' not in session:
        flash('No compliance data found. Please start a new scan.', 'error')
        return redirect(url_for('compliance'))
    
    data = session['compliance_data']
    
    # Auto-discover targets
    discovery_result = auto_discover_targets(data['service_type'], data['target_input'])
    
    # Store discovery result in session for the next step
    session['discovery_result'] = discovery_result
    
    return render_template('compliance_results.html', 
                         data=data, 
                         discovery_result=discovery_result)

@app.route('/compliance/scan', methods=['POST'])
def run_compliance_scan():
    try:
        print("DEBUG: Starting compliance scan...")
        
        if 'discovery_result' not in session:
            print("DEBUG: No discovery data found in session")
            return jsonify({'error': 'No discovery data found'}), 400
        
        discovery_result = session['discovery_result']
        compliance_data = session.get('compliance_data', {})
        
        print(f"DEBUG: Form data received: {request.form}")
        print(f"DEBUG: Discovery result: {discovery_result}")
        print(f"DEBUG: Compliance data: {compliance_data}")
        
        # Get selected targets from form
        selected_targets = []
        
        # Process discovered targets
        for i, target in enumerate(discovery_result['discovered_targets']):
            if f'target_{i}' in request.form:
                selected_targets.append(target)
                print(f"DEBUG: Added discovered target {i}: {target}")
        
        # Process manual targets
        for i, target in enumerate(discovery_result['manual_targets']):
            if f'target_manual_{i}' in request.form:
                selected_targets.append(target)
                print(f"DEBUG: Added manual target {i}: {target}")
        
        print(f"DEBUG: Total selected targets: {len(selected_targets)}")
        
        if not selected_targets:
            print("DEBUG: No targets selected")
            return jsonify({'error': 'No targets selected'}), 400
        
        # Run compliance scan
        results = []
        scan_date = datetime.datetime.now()
        service_type = compliance_data.get('service_type', 'Unknown')
        domain = compliance_data.get('domain_input', '')
        
        print(f"DEBUG: Starting scan for {len(selected_targets)} targets")
        print(f"DEBUG: Service type: {service_type}")
        print(f"DEBUG: Domain: {domain}")
        
        if service_type not in COMPLIANCE_TYPES:
            print(f"DEBUG: Invalid service type: {service_type}")
            return jsonify({'error': f'Invalid service type: {service_type}'}), 400
        
        for target in selected_targets:
            ip_address = target['ip']
            hostname = target.get('hostname', 'Unknown')
            
            print(f"DEBUG: Scanning target {hostname} ({ip_address})")
            
            # Get parameters for this service type
            params = COMPLIANCE_TYPES[service_type]["parameters"]
            
            for param_info in params:
                check_func_name = param_info["check_function"]
                print(f"DEBUG: Running check {check_func_name} for {ip_address}")
                
                if check_func_name not in CHECK_FUNCTIONS:
                    print(f"DEBUG: Check function {check_func_name} not found in CHECK_FUNCTIONS")
                    # Add error result for missing function
                    error_result = {
                        'scan_date': scan_date,
                        'service_type': str(service_type),
                        'ip_address': str(ip_address),
                        'sr_no': int(param_info.get('sr_no', 0)),
                        'parameter': str(param_info.get('parameter', '')),
                        'compliance_status': 'Error',
                        'threat_level': str(param_info.get('threat_level', 'Info')),
                        'remarks': f'Check function {check_func_name} not implemented',
                        'command_used': str(param_info.get('command', '')),
                        'hostname': str(hostname),
                        'target_type': str(target.get('type', 'unknown')),
                        'domain': str(domain) if domain else ''
                    }
                    results.append(error_result)
                    continue
                
                try:
                    print(f"DEBUG: Calling {check_func_name}({ip_address}, {domain})")
                    
                    if domain:
                        compliance_status, remarks = CHECK_FUNCTIONS[check_func_name](ip_address, domain)
                    else:
                        compliance_status, remarks = CHECK_FUNCTIONS[check_func_name](ip_address)
                    
                    print(f"DEBUG: Check {check_func_name} returned: {compliance_status}, {remarks}")
                    
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
                    
                    results.append(result)
                    print(f"DEBUG: Check completed successfully: {compliance_status}")
                    
                except Exception as e:
                    print(f"DEBUG: Check {check_func_name} failed with error: {str(e)}")
                    import traceback
                    traceback.print_exc()
                    
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
                    results.append(error_result)
        
        print(f"DEBUG: Scan completed. Total results: {len(results)}")
        
        # Save results to database
        saved_count = 0
        if results:
            try:
                saved_count = save_to_db(results)
                print(f"DEBUG: Saved {saved_count} results to database")
            except Exception as e:
                print(f"DEBUG: Database save failed: {str(e)}")
                import traceback
                traceback.print_exc()
                saved_count = 0
            
            session['scan_results'] = results
            session['saved_count'] = saved_count
        
        return jsonify({
            'success': True,
            'results_count': len(results),
            'saved_count': saved_count
        })
        
    except Exception as e:
        print(f"DEBUG: Route error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Scan failed: {str(e)}'}), 500

@app.route('/compliance/final-results')
def final_compliance_results():
    if 'scan_results' not in session:
        flash('No scan results found. Please run a scan first.', 'error')
        return redirect(url_for('compliance'))
    
    results = session['scan_results']
    saved_count = session.get('saved_count', 0)
    compliance_data = session.get('compliance_data', {})
    
    return render_template('final_compliance_results.html', 
                         results=results, 
                         saved_count=saved_count,
                         compliance_data=compliance_data)

@app.route('/dashboard')
def dashboard():
    try:
        conn = sqlite3.connect('compliance_results.db')
        
        # Get basic statistics
        total_scans_query = """
            SELECT COUNT(DISTINCT ip_address || service_type || DATE(scan_date)) as total_scans
            FROM compliance_results
        """
        total_scans = conn.execute(total_scans_query).fetchone()[0]
        
        unique_ips_query = "SELECT COUNT(DISTINCT ip_address) FROM compliance_results"
        unique_ips = conn.execute(unique_ips_query).fetchone()[0]
        
        services_query = "SELECT COUNT(DISTINCT service_type) FROM compliance_results"
        services_count = conn.execute(services_query).fetchone()[0]
        
        # Get recent scans
        recent_scans_query = """
            SELECT service_type, ip_address, parameter, compliance_status, threat_level, scan_date 
            FROM compliance_results 
            ORDER BY scan_date DESC
            LIMIT 20
        """
        recent_scans = pd.read_sql_query(recent_scans_query, conn)
        
        # Get compliance by service type
        service_compliance_query = """
            SELECT service_type, 
                   COUNT(*) as total_checks,
                   SUM(CASE WHEN compliance_status = 'Yes' THEN 1 ELSE 0 END) as compliant,
                   SUM(CASE WHEN compliance_status = 'No' THEN 1 ELSE 0 END) as non_compliant,
                   SUM(CASE WHEN compliance_status = 'Error' THEN 1 ELSE 0 END) as errors
            FROM compliance_results 
            GROUP BY service_type
        """
        service_compliance = pd.read_sql_query(service_compliance_query, conn)
        
        # Get threat level distribution
        threat_dist_query = """
            SELECT threat_level, COUNT(*) as count
            FROM compliance_results 
            GROUP BY threat_level
        """
        threat_dist = pd.read_sql_query(threat_dist_query, conn)
        
        conn.close()
        
        return render_template('dashboard.html', 
                             total_scans=total_scans,
                             unique_ips=unique_ips,
                             services_count=services_count,
                             recent_scans=recent_scans,
                             service_compliance=service_compliance,
                             threat_dist=threat_dist)
        
    except Exception as e:
        flash(f'Error loading dashboard data: {str(e)}', 'error')
        return render_template('dashboard.html', 
                             total_scans=0,
                             unique_ips=0,
                             services_count=0,
                             recent_scans=pd.DataFrame(),
                             service_compliance=pd.DataFrame(),
                             threat_dist=pd.DataFrame())

@app.route('/reports')
def reports():
    import sqlite3
    import pandas as pd
    conn = sqlite3.connect('compliance_results.db')
    # Group by scan_date, ip_address, service_type, domain, hostname
    scans_query = '''
        SELECT MIN(id) as id, scan_date, ip_address, service_type, domain, hostname
        FROM compliance_results
        GROUP BY scan_date, ip_address, service_type, domain, hostname
        ORDER BY scan_date DESC
    '''
    scans_df = pd.read_sql_query(scans_query, conn)
    conn.close()
    scans = scans_df.to_dict('records')
    return render_template('reports.html', scans=scans)

@app.route('/reports', methods=['POST'])
def generate_report():
    try:
        report_type = request.form.get('report_type')
        output_format = request.form.get('format')
        date_from = request.form.get('date_from')
        date_to = request.form.get('date_to')
        service_type = request.form.get('service_type')
        compliance_status = request.form.get('compliance_status')
        threat_level = request.form.get('threat_level')
        ip_address = request.form.get('ip_address')
        
        # Build query
        query = "SELECT * FROM compliance_results WHERE 1=1"
        params = []
        
        if date_from:
            query += " AND DATE(scan_date) >= ?"
            params.append(date_from)
        
        if date_to:
            query += " AND DATE(scan_date) <= ?"
            params.append(date_to)
        
        if service_type:
            query += " AND service_type = ?"
            params.append(service_type)
        
        if compliance_status:
            query += " AND compliance_status = ?"
            params.append(compliance_status)
        
        if threat_level:
            query += " AND threat_level = ?"
            params.append(threat_level)
        
        if ip_address:
            query += " AND ip_address = ?"
            params.append(ip_address)
        
        # Apply report type filters
        if report_type == 'issues':
            query += " AND (compliance_status = 'No' OR compliance_status = 'Error')"
        elif report_type == 'compliance':
            query += " AND compliance_status IN ('Yes', 'No')"
        
        query += " ORDER BY scan_date DESC"
        
        conn = sqlite3.connect('compliance_results.db')
        df = pd.read_sql_query(query, conn, params=params)
        conn.close()
        
        if df.empty:
            flash('No data found matching your criteria.', 'warning')
            return redirect(url_for('reports'))
        
        # Generate report based on format
        if output_format == 'csv':
            csv_data = df.to_csv(index=False)
            return Response(
                csv_data,
                mimetype='text/csv',
                headers={'Content-Disposition': f'attachment; filename=compliance_report_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'}
            )
        elif output_format == 'json':
            json_data = df.to_json(orient='records', indent=2)
            return Response(
                json_data,
                mimetype='application/json',
                headers={'Content-Disposition': f'attachment; filename=compliance_report_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.json'}
            )
        else:  # HTML
            return render_template('report_result.html', 
                                 data=df.to_dict('records'),
                                 report_type=report_type,
                                 filters={
                                     'date_from': date_from,
                                     'date_to': date_to,
                                     'service_type': service_type,
                                     'compliance_status': compliance_status,
                                     'threat_level': threat_level,
                                     'ip_address': ip_address
                                 },
                                 generated_time=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            )
    
    except Exception as e:
        flash(f'Error generating report: {str(e)}', 'error')
        return redirect(url_for('reports'))

@app.route('/reports/quick/<report_type>')
def quick_report(report_type):
    try:
        conn = sqlite3.connect('compliance_results.db')
        
        if report_type == 'summary':
            # Summary statistics
            summary_query = """
                SELECT 
                    COUNT(DISTINCT ip_address || service_type || DATE(scan_date)) as total_scans,
                    COUNT(DISTINCT ip_address) as unique_ips,
                    COUNT(DISTINCT service_type) as services_count,
                    SUM(CASE WHEN compliance_status = 'Yes' THEN 1 ELSE 0 END) as compliant_count,
                    SUM(CASE WHEN compliance_status = 'No' THEN 1 ELSE 0 END) as non_compliant_count,
                    SUM(CASE WHEN compliance_status = 'Error' THEN 1 ELSE 0 END) as error_count
                FROM compliance_results
            """
            summary = conn.execute(summary_query).fetchone()
            
            # Recent data for display
            recent_query = "SELECT * FROM compliance_results ORDER BY scan_date DESC LIMIT 50"
            recent_data = pd.read_sql_query(recent_query, conn)
            
            conn.close()
            
            return render_template('quick_summary.html', 
                                 summary=summary,
                                 recent_data=recent_data.to_dict('records'))
        
        elif report_type == 'issues':
            # Only non-compliant and error items
            issues_query = """
                SELECT * FROM compliance_results 
                WHERE compliance_status IN ('No', 'Error')
                ORDER BY threat_level DESC, scan_date DESC
            """
            issues_data = pd.read_sql_query(issues_query, conn)
            conn.close()
            
            return render_template('quick_issues.html', 
                                 issues_data=issues_data.to_dict('records'))
        
        elif report_type == 'compliance':
            # Compliance status breakdown
            compliance_query = """
                SELECT 
                    service_type,
                    compliance_status,
                    COUNT(*) as count
                FROM compliance_results 
                WHERE compliance_status IN ('Yes', 'No')
                GROUP BY service_type, compliance_status
                ORDER BY service_type, compliance_status
            """
            compliance_data = pd.read_sql_query(compliance_query, conn)
            conn.close()
            
            return render_template('quick_compliance.html', 
                                 compliance_data=compliance_data.to_dict('records'))
        
        elif report_type == 'recent':
            # Recent scans
            recent_query = """
                SELECT * FROM compliance_results 
                ORDER BY scan_date DESC 
                LIMIT 100
            """
            recent_data = pd.read_sql_query(recent_query, conn)
            conn.close()
            
            return render_template('quick_recent.html', 
                                 recent_data=recent_data.to_dict('records'))
        
        else:
            flash('Invalid report type.', 'error')
            return redirect(url_for('reports'))
    
    except Exception as e:
        flash(f'Error generating quick report: {str(e)}', 'error')
        return redirect(url_for('reports'))

@app.route('/download_report')
def download_report():
    scan_id = request.args.get('scan_id')
    if scan_id:
        import sqlite3
        conn = sqlite3.connect('compliance_results.db')
        # Get all rows for this scan id
        scan_query = 'SELECT * FROM compliance_results WHERE id = ?'
        scan_rows = conn.execute(scan_query, (scan_id,)).fetchall()
        columns = [desc[0] for desc in conn.execute(scan_query, (scan_id,)).description]
        conn.close()
        if not scan_rows:
            flash('No scan found with the specified ID.', 'error')
            return redirect(url_for('reports'))
        # Convert to list of dicts
        results = [dict(zip(columns, row)) for row in scan_rows]
        # Compose scan_info for the PDF summary
        scan_info = {
            'service_type': results[0].get('service_type', 'N/A'),
            'ip_address': results[0].get('ip_address', ''),
            'scan_date': results[0].get('scan_date', ''),
            'domain': results[0].get('domain', ''),
            'hostname': results[0].get('hostname', '')
        }
        pdf_buffer = generate_pdf_report(results, scan_info)
        return send_file(
            pdf_buffer,
            as_attachment=True,
            download_name=f"compliance_report_{scan_info['service_type'].replace('/', '_')}_{scan_info['scan_date']}.pdf",
            mimetype='application/pdf'
        )
    # Fallback to old session-based download
    if 'scan_results' not in session or 'compliance_data' not in session:
        flash('No scan results found. Please run a scan first.', 'error')
        return redirect(url_for('compliance'))
    results = session['scan_results']
    compliance_data = session['compliance_data']
    scan_info = {
        'service_type': compliance_data.get('service_type', 'N/A'),
        'ip_address': ', '.join(sorted(set(r.get('ip_address', '') for r in results))),
        'scan_date': results[0]['scan_date'] if results else '',
        'domain': compliance_data.get('domain', ''),
        'hostname': ', '.join(sorted(set(r.get('hostname', '') for r in results if r.get('hostname', '') != 'manual')))
    }
    pdf_buffer = generate_pdf_report(results, scan_info)
    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name=f"compliance_report_{scan_info['service_type'].replace('/', '_')}_{scan_info['scan_date']}.pdf",
        mimetype='application/pdf'
    )

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
