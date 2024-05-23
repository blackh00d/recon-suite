import subprocess
import os
import sys
import sqlite3
import re

DB = "recon_data.db"
OUT_DIR = "recon_results"

# Ensure the script is running with necessary permissions
def ensure_permissions():
    if os.geteuid() != 0:
        print("This script must be run as root. Please rerun it with 'sudo'.")
        sys.exit(1)

# Function to check if a command exists
def command_exists(command):
    return subprocess.call(f"type {command}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0

# Function to install necessary tools
def install_tools():
    tools = ["sqlite3", "nmap", "masscan", "sublist3r", "theHarvester", "amass", "whatweb", "dnsenum", "sslyze", "nikto", "sqlmap", "nosqlmap", "commix", "hydra", "medusa", "john", "xsstrike", "xsser", "dependency-check", "gobuster"]
    missing_tools = [tool for tool in tools if not command_exists(tool)]
    if missing_tools:
        print(f"Installing missing tools: {', '.join(missing_tools)}")
        for tool in missing_tools:
            subprocess.run(f"sudo apt-get install -y {tool}", shell=True)
        # Download and install specific tools if needed (e.g., jSQL Injection)
        if "java" in missing_tools:
            subprocess.run("sudo apt-get install -y default-jdk", shell=True)
        if "john" in missing_tools:
            subprocess.run("sudo apt-get install -y john", shell=True)
        if "dependency-check" in missing_tools:
            subprocess.run("wget https://dl.bintray.com/jeremy-long/owasp/dependency-check-5.3.2-release.zip", shell=True)
            subprocess.run("unzip dependency-check-5.3.2-release.zip", shell=True)
            subprocess.run("chmod +x dependency-check/bin/dependency-check.sh", shell=True)

# Function to prompt for necessary files (e.g., username or password lists)
def prompt_for_files():
    user_list = input("Enter the path to the username list (leave empty for default 'users.txt'): ") or "users.txt"
    if not os.path.exists(user_list):
        print(f"Username list file '{user_list}' not found. Exiting.")
        sys.exit(1)

    password_list = input("Enter the path to the password list (leave empty for default 'passwords.txt'): ") or "passwords.txt"
    if not os.path.exists(password_list):
        print(f"Password list file '{password_list}' not found. Exiting.")
        sys.exit(1)

    return user_list, password_list

# Initialize SQLite Database
def initialize_db():
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS nmap_results (
        id INTEGER PRIMARY KEY,
        ip TEXT,
        port INTEGER,
        service TEXT,
        version TEXT
    );
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS subdomains (
        id INTEGER PRIMARY KEY,
        domain TEXT,
        subdomain TEXT
    );
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS emails (
        id INTEGER PRIMARY KEY,
        domain TEXT,
        email TEXT
    );
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS technologies (
        id INTEGER PRIMARY KEY,
        domain TEXT,
        technology TEXT
    );
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS dns_info (
        id INTEGER PRIMARY KEY,
        domain TEXT,
        dns_record TEXT
    );
    """)
    conn.commit()
    conn.close()

# Function to store Nmap results in the database
def store_nmap_results(output_file):
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()
    with open(output_file, 'r') as file:
        lines = file.readlines()
    for line in lines:
        if 'open' in line:
            ip = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)[0]
            parts = line.split()
            port = parts[0].split('/')[0]
            service = parts[2]
            version = ' '.join(parts[3:])
            cursor.execute("INSERT INTO nmap_results (ip, port, service, version) VALUES (?, ?, ?, ?)", (ip, port, service, version))
    conn.commit()
    conn.close()

# Function to run a command and return the output
def run_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode('utf-8')
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {command}")
        print(e.output.decode('utf-8'))
        return ""

# Function to run Nmap and return the open web ports and services
def run_nmap(target):
    nmap_command = f"nmap -p 80,443 -sV -oN {OUT_DIR}/nmap_scan.txt {target}"
    print(f"Running Nmap: {nmap_command}")
    run_command(nmap_command)
    store_nmap_results(f"{OUT_DIR}/nmap_scan.txt")
    return f"{OUT_DIR}/nmap_scan.txt"

# Function to extract web ports from Nmap output
def extract_web_ports_from_nmap(output_file):
    web_services = []
    with open(output_file, 'r') as file:
        lines = file.readlines()
    for line in lines:
        if re.search(r'80/tcp|443/tcp', line):
            ip = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
            if ip:
                service = line.split()[2]
                web_services.append((ip[0], service))
    return web_services

# Function to run SQLmap
def run_sqlmap(target):
    sqlmap_command = f"sqlmap -u {target} --batch --output-dir={OUT_DIR}/sqlmap_output"
    print(f"Running SQLmap: {sqlmap_command}")
    run_command(sqlmap_command)

# Function to run NoSQLMap
def run_nosqlmap(target):
    nosqlmap_command = f"nosqlmap -u {target} --output={OUT_DIR}/nosqlmap_output"
    print(f"Running NoSQLMap: {nosqlmap_command}")
    run_command(nosqlmap_command)

# Function to run Commix
def run_commix(target):
    commix_command = f"commix --url={target} --batch --output-dir={OUT_DIR}/commix_output"
    print(f"Running Commix: {commix_command}")
    run_command(commix_command)

# Function to run jSQL Injection
def run_jsql(target):
    jsql_command = f"java -jar jsql-injection-v0.79.jar -u {target} -o {OUT_DIR}/jsql_output"
    print(f"Running jSQL Injection: {jsql_command}")
    run_command(jsql_command)

# Function to run BBQSQL
def run_bbqsql(target):
    bbqsql_command = f"bbqsql -u {target} -o {OUT_DIR}/bbqsql_output"
    print(f"Running BBQSQL: {bbqsql_command}")
    run_command(bbqsql_command)

# Function to run Hydra
def run_hydra(target, user_list, password_list):
    hydra_command = f"hydra -L {user_list} -P {password_list} {target} http-get"
    print(f"Running Hydra: {hydra_command}")
    run_command(hydra_command)

# Function to run Medusa
def run_medusa(target, user_list, password_list):
    medusa_command = f"medusa -h {target} -U {user_list} -P {password_list} -M http"
    print(f"Running Medusa: {medusa_command}")
    run_command(medusa_command)

# Function to run John the Ripper (example with a sample hash file)
def run_john(password_list):
    john_command = f"john --wordlist={password_list} hash_file.txt"
    print(f"Running John the Ripper: {john_command}")
    run_command(john_command)

# Function to run Burp Suite (example with headless mode)
def run_burpsuite(target):
    burp_command = f"java -jar burpsuite_pro_v2021.7.1.jar --collaborator-server --target={target}"
    print(f"Running Burp Suite: {burp_command}")
    run_command(burpsuite_command)

# Function to run SSLyze
def run_sslyze(target):
    sslyze_command = f"sslyze --regular {target} --json_out={OUT_DIR}/sslyze.json"
    print(f"Running SSLyze: {sslyze_command}")
    run_command(sslyze_command)

# Function to run Lynis
def run_lynis():
    lynis_command = "lynis audit system"
    print(f"Running Lynis: {lynis_command}")
    run_command(lynis_command)

# Function to run XSStrike
def run_xsstrike(target):
    xsstrike_command = f"xsstrike -u {target}"
    print(f"Running XSStrike: {xsstrike_command}")
    run_command(xsstrike_command)

# Function to run XSSer
def run_xsser(target):
    xsser_command = f"xsser --url {target}"
    print(f"Running XSSer: {xsser_command}")
    run_command(xsser_command)

# Function to run OWASP Dependency-Check (example with a sample project)
def run_dependency_check():
    dependency_check_command = f"dependency-check --project Sample --scan {OUT_DIR}/dependency-check-output"
    print(f"Running OWASP Dependency-Check: {dependency_check_command}")
    run_command(dependency_check_command)

# Function to run Nessus (assuming Nessus is installed and the scanner is running)
def run_nessus(target):
    nessus_command = f"nessus -q -x -T html -o {OUT_DIR}/nessus_output.html -t {target}"
    print(f"Running Nessus: {nessus_command}")
    run_command(nessus_command)

# Function to run Nikto
def run_nikto(target):
    nikto_command = f"nikto -h {target} -output {OUT_DIR}/nikto_scan.txt"
    print(f"Running Nikto: {nikto_command}")
    run_command(nikto_command)

# Function to run Gobuster
def run_gobuster(target):
    gobuster_command = f"gobuster dir -u {target} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o {OUT_DIR}/gobuster_output.txt"
    print(f"Running Gobuster: {gobuster_command}")
    run_command(gobuster_command)

# Function to run additional reconnaissance tools and store results
def run_additional_tools(target):
    # Run Masscan
    masscan_command = f"masscan -p1-65535 {target} --rate=1000 -oX {OUT_DIR}/masscan_scan.xml"
    print(f"Running Masscan: {masscan_command}")
    run_command(masscan_command)

    # Run Sublist3r
    sublist3r_command = f"sublist3r -d {target} -o {OUT_DIR}/subdomains.txt"
    print(f"Running Sublist3r: {sublist3r_command}")
    run_command(sublist3r_command)
    store_subdomains(f"{OUT_DIR}/subdomains.txt", target)

    # Run theHarvester
    theHarvester_command = f"theHarvester -d {target} -l 500 -b google -f {OUT_DIR}/theHarvester.xml"
    print(f"Running theHarvester: {theHarvester_command}")
    run_command(theHarvester_command)
    store_emails(f"{OUT_DIR}/theHarvester.xml", target)

    # Run Amass
    amass_command = f"amass enum -d {target} -o {OUT_DIR}/amass.txt"
    print(f"Running Amass: {amass_command}")
    run_command(amass_command)
    store_subdomains(f"{OUT_DIR}/amass.txt", target)

    # Run WhatWeb
    whatweb_command = f"whatweb {target} --log-xml={OUT_DIR}/whatweb.xml"
    print(f"Running WhatWeb: {whatweb_command}")
    run_command(whatweb_command)
    store_technologies(f"{OUT_DIR}/whatweb.xml", target)

    # Run Dnsenum
    dnsenum_command = f"dnsenum {target} > {OUT_DIR}/dnsenum.txt"
    print(f"Running Dnsenum: {dnsenum_command}")
    run_command(dnsenum_command)
    store_dns_info(f"{OUT_DIR}/dnsenum.txt", target)

def store_subdomains(file_path, target):
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()
    with open(file_path, 'r') as file:
        for line in file:
            subdomain = line.strip()
            cursor.execute("INSERT INTO subdomains (domain, subdomain) VALUES (?, ?)", (target, subdomain))
    conn.commit()
    conn.close()

def store_emails(file_path, target):
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()
    with open(file_path, 'r') as file:
        data = file.read()
    emails = re.findall(r'<email>(.*?)</email>', data)
    for email in emails:
        cursor.execute("INSERT INTO emails (domain, email) VALUES (?, ?)", (target, email))
    conn.commit()
    conn.close()

def store_technologies(file_path, target):
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()
    with open(file_path, 'r') as file:
        data = file.read()
    technologies = re.findall(r'<plugin id="(.*?)"', data)
    for tech in technologies:
        cursor.execute("INSERT INTO technologies (domain, technology) VALUES (?, ?)", (target, tech))
    conn.commit()
    conn.close()

def store_dns_info(file_path, target):
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()
    with open(file_path, 'r') as file:
        data = file.read()
    dns_records = re.findall(r'Host: (.*?)\s', data)
    for record in dns_records:
        cursor.execute("INSERT INTO dns_info (domain, dns_record) VALUES (?, ?)", (target, record))
    conn.commit()
    conn.close()

# Main function
def main(target):
    ensure_permissions()
    install_tools()
    user_list, password_list = prompt_for_files()

    os.makedirs(OUT_DIR, exist_ok=True)
    initialize_db()

    nmap_output_file = run_nmap(target)
    web_services = extract_web_ports_from_nmap(nmap_output_file)
    
    for ip, service in web_services:
        print(f"Processing IP: {ip} with service: {service}")
        url = f"http://{ip}" if service == "http" else f"https://{ip}"
        
        run_sqlmap(url)
        run_nosqlmap(url)
        run_commix(url)
        run_jsql(url)
        run_bbqsql(url)
        run_hydra(url, user_list, password_list)
        run_medusa(url, user_list, password_list)
        run_john(password_list)
        run_burpsuite(url)
        run_sslyze(url)
        run_lynis()
        run_xsstrike(url)
        run_xsser(url)
        run_dependency_check()
        run_nessus(url)
        run_nikto(url)
        run_gobuster(url)
        
    run_additional_tools(target)
    print(f"Reconnaissance completed. Data stored in {DB}.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: sudo python3 automation_script.py <target>")
        sys.exit(1)
    target = sys.argv[1]
    main(target)
