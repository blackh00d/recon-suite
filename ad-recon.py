import subprocess
import os
import sys

DB = "ad_recon_data.db"
OUT_DIR = "ad_recon_results"

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
    tools = ["sqlite3", "powershell", "cmd"]
    missing_tools = [tool for tool in tools if not command_exists(tool)]
    if missing_tools:
        print(f"Missing tools detected: {', '.join(missing_tools)}")
        for tool in missing_tools:
            print(f"Please ensure {tool} is installed and available in your PATH.")
        sys.exit(1)

# Initialize SQLite Database
def initialize_db():
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ad_recon (
        id INTEGER PRIMARY KEY,
        category TEXT,
        command TEXT,
        output TEXT
    );
    """)
    conn.commit()
    conn.close()

# Function to run a command and log the output
def run_command(command, category):
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode('utf-8')
        store_ad_recon_results(category, command, output)
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {command}")
        print(e.output.decode('utf-8'))

# Function to store AD recon results in the database
def store_ad_recon_results(category, command, output):
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO ad_recon (category, command, output) VALUES (?, ?, ?)", (category, command, output))
    conn.commit()
    conn.close()

# Function to run PowerShell commands for AD recon
def run_powershell_commands():
    powershell_commands = {
        "Domain Information": "Get-ADDomain | Format-List",
        "Forest Information": "Get-ADForest | Format-List",
        "Domain Controllers": "Get-ADDomainController -Filter * | Format-Table",
        "AD Sites": "Get-ADReplicationSite -Filter * | Format-Table",
        "Users": "Get-ADUser -Filter * -Property * | Format-Table Name, DistinguishedName, LastLogonDate",
        "Groups": "Get-ADGroup -Filter * | Format-Table Name, GroupScope, GroupCategory",
        "Computers": "Get-ADComputer -Filter * | Format-Table Name, DistinguishedName, OperatingSystem",
        "GPOs": "Get-GPO -All | Format-Table DisplayName, GpoStatus, CreationTime",
        "Service Accounts": "Get-ADServiceAccount -Filter * | Format-Table Name, SamAccountName",
        "Trusts": "Get-ADTrust -Filter * | Format-Table Name, Source, Target, TrustType, TrustDirection"
    }
    for category, command in powershell_commands.items():
        run_command(f"powershell -Command \"{command}\"", category)

# Function to run CMD commands for AD recon
def run_cmd_commands():
    cmd_commands = {
        "Network Shares": "net view /all",
        "Domain Info": "nltest /dsgetdc:example.com",
        "Logon Servers": "nltest /dclist:example.com",
        "Trust Relationships": "nltest /trusted_domains",
        "Sessions": "net session",
        "Open Files": "net file"
    }
    for category, command in cmd_commands.items():
        run_command(command, category)

# Main function
def main(target):
    ensure_permissions()
    install_tools()

    os.makedirs(OUT_DIR, exist_ok=True)
    initialize_db()

    run_powershell_commands()
    run_cmd_commands()

    print(f"Active Directory reconnaissance completed. Data stored in {DB}.")

if __name__ == "__main__":
    main()
