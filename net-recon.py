#!/usr/bin/python3

import subprocess
import os
import sys
import re

DB = "network_recon_data.db"
OUT_DIR = "network_recon_results"

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
    tools = ["sqlite3", "nmap", "masscan", "crackmapexec", "impacket-scripts", "nikto", "gobuster"]
    missing_tools = [tool for tool in tools if not command_exists(tool)]
    if missing_tools:
        print(f"Installing missing tools: {', '.join(missing_tools)}")
        for tool in missing_tools:
            subprocess.run(f"sudo apt-get install -y {tool}", shell=True)
        if "impacket-scripts" in missing_tools:
            subprocess.run("pip install impacket", shell=True)

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

# Function to perform a quick Nmap scan
def quick_nmap_scan(target):
    nmap_command = f"nmap -p- --open -T4 -oN {OUT_DIR}/quick_nmap_scan.txt {target}"
    print(f"Running quick Nmap scan: {nmap_command}")
    run_command(nmap_command)
    return f"{OUT_DIR}/quick_nmap_scan.txt"

# Function to perform a detailed Nmap scan
def detailed_nmap_scan(ip, port):
    nmap_command = f"nmap -p {port} -A --script=default,vuln -oN {OUT_DIR}/detailed_nmap_scan_{ip}_{port}.txt {ip}"
    print(f"Running detailed Nmap scan on {ip}:{port}: {nmap_command}")
    run_command(nmap_command)

# Function to extract open ports from Nmap output
def extract_open_ports(output_file):
    open_ports = []
    with open(output_file, 'r') as file:
        lines = file.readlines()
    for line in lines:
        if 'open' in line:
            ip = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)[0]
            port = line.split('/')[0]
            open_ports.append((ip, port))
    return open_ports

# Function to run Nikto for web port analysis
def run_nikto(target):
    nikto_command = f"nikto -h {target} -output {OUT_DIR}/nikto_scan_{target.replace(':', '_')}.txt"
    print(f"Running Nikto on {target}: {nikto_command}")
    run_command(nikto_command)

# Function to run Gobuster for web directory brute-forcing
def run_gobuster(target):
    gobuster_command = f"gobuster dir -u {target} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o {OUT_DIR}/gobuster_output_{target.replace(':', '_')}.txt"
    print(f"Running Gobuster on {target}: {gobuster_command}")
    run_command(gobuster_command)

# Function to run CrackMapExec for SMB analysis
def run_crackmapexec(target):
    cme_command = f"crackmapexec smb {target} > {OUT_DIR}/crackmapexec_{target}.txt"
    print(f"Running CrackMapExec on {target}: {cme_command}")
    run_command(cme_command)

# Function to run Impacket scripts for SMB analysis
def run_impacket_scripts(target):
    impacket_command = f"impacket-smbclient {target}"
    print(f"Running Impacket on {target}: {impacket_command}")
    run_command(impacket_command)

# Main function
def main(target):
    ensure_permissions()
    install_tools()

    os.makedirs(OUT_DIR, exist_ok=True)
    initialize_db()

    quick_scan_output = quick_nmap_scan(target)
    open_ports = extract_open_ports(quick_scan_output)
    
    for ip, port in open_ports:
        detailed_nmap_scan(ip, port)

        if port in ["80", "443"]:
            url = f"http://{ip}:{port}" if port == "80" else f"https://{ip}:{port}"
            run_nikto(url)
            run_gobuster(url)

        if port in ["139", "445"]:
            run_crackmapexec(ip)
            run_impacket_scripts(ip)

    print(f"Recon completed. Data stored in {DB}.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: sudo python3 network_recon_automation.py <target>")
        sys.exit(1)
    target = sys.argv[1]
    main(target)
