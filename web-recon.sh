#!/bin/bash

# Dependencies: sqlite3, nmap, masscan, recon-ng, sublist3r, theHarvester, amass, whatweb, dnsenum, sslyze, nikto

TARGET=$1
DB="recon_data.db"
OUT_DIR="recon_results"
mkdir -p $OUT_DIR

# Initialize SQLite Database
sqlite3 $DB <<EOF
CREATE TABLE IF NOT EXISTS nmap_results (
    id INTEGER PRIMARY KEY,
    ip TEXT,
    port INTEGER,
    service TEXT,
    version TEXT
);
CREATE TABLE IF NOT EXISTS subdomains (
    id INTEGER PRIMARY KEY,
    domain TEXT,
    subdomain TEXT
);
CREATE TABLE IF NOT EXISTS emails (
    id INTEGER PRIMARY KEY,
    domain TEXT,
    email TEXT
);
CREATE TABLE IF NOT EXISTS technologies (
    id INTEGER PRIMARY KEY,
    domain TEXT,
    technology TEXT
);
CREATE TABLE IF NOT EXISTS dns_info (
    id INTEGER PRIMARY KEY,
    domain TEXT,
    dns_record TEXT
);
EOF

# Function to store Nmap results in the database
store_nmap_results() {
    while read line; do
        if [[ $line == *open* ]]; then
            ip=$(echo $line | awk '{print $2}')
            port=$(echo $line | awk '{print $1}' | cut -d'/' -f1)
            service=$(echo $line | awk '{print $3}')
            version=$(echo $line | cut -d' ' -f4-)
            sqlite3 $DB "INSERT INTO nmap_results (ip, port, service, version) VALUES ('$ip', $port, '$service', '$version');"
        fi
    done < "$OUT_DIR/nmap_scan.txt"
}

# Run Nmap and store results
nmap -sS -p 1-65535 -T4 -A -v $TARGET -oN $OUT_DIR/nmap_scan.txt
store_nmap_results

# Run Masscan
masscan -p1-65535 $TARGET --rate=1000 -oX $OUT_DIR/masscan_scan.xml

# Run Sublist3r and store results
sublist3r -d $TARGET -o $OUT_DIR/subdomains.txt
while read subdomain; do
    sqlite3 $DB "INSERT INTO subdomains (domain, subdomain) VALUES ('$TARGET', '$subdomain');"
done < "$OUT_DIR/subdomains.txt"

# Run theHarvester and store results
theHarvester -d $TARGET -l 500 -b google -f $OUT_DIR/theHarvester.xml
emails=$(cat $OUT_DIR/theHarvester.xml | grep -oP '(?<=<email>)[^<]+')
for email in $emails; do
    sqlite3 $DB "INSERT INTO emails (domain, email) VALUES ('$TARGET', '$email');"
done

# Run Amass and store results
amass enum -d $TARGET -o $OUT_DIR/amass.txt
while read subdomain; do
    sqlite3 $DB "INSERT INTO subdomains (domain, subdomain) VALUES ('$TARGET', '$subdomain');"
done < "$OUT_DIR/amass.txt"

# Run WhatWeb and store results
whatweb $TARGET --log-xml=$OUT_DIR/whatweb.xml
technologies=$(cat $OUT_DIR/whatweb.xml | grep -oP '(?<=<plugin id=")[^"]+')
for tech in $technologies; do
    sqlite3 $DB "INSERT INTO technologies (domain, technology) VALUES ('$TARGET', '$tech');"
done

# Run Dnsenum and store results
dnsenum $TARGET > $OUT_DIR/dnsenum.txt
dns_records=$(cat $OUT_DIR/dnsenum.txt | grep -oP '(?<=Host: )[^ ]+')
for record in $dns_records; do
    sqlite3 $DB "INSERT INTO dns_info (domain, dns_record) VALUES ('$TARGET', '$record');"
done

# Run SSLyze and store results
sslyze --regular $TARGET --json_out=$OUT_DIR/sslyze.json
# Parse and store SSLyze results as needed

# Run Nikto and store results
nikto -h $TARGET -output $OUT_DIR/nikto_scan.txt
# Parse and store Nikto results as needed

echo "Reconnaissance completed. Data stored in $DB."
