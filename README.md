# SOAR-Threat-Detection-Response
**The primary objective of this project is to demonstrate the power of SOAR (Security Orchestration, Automation, and Response) by automating the transition from a "Passive Alert" (knowing you are being attacked) to an "Active Defense" (stopping the attack).**

The SOAR Threat Detection and Response System is an automated, multi-layered cybersecurity framework designed to reduce the **"Mean Time to Respond" (MTTR)** to network-based attacks. It integrates a **Network Intrusion Detection System (NIDS)** with a Security Information and Event Management (SIEM) stack to orchestrate real-time, autonomous firewall mitigation without human intervention.
## Core Components
* **The Detector (Suricata):** Acts as the eyes of the system, identifying malicious traffic patterns (signatures).
*	**The Transport (Filebeat/Logstash):** Acts as the nervous system, moving and refining raw alert data into usable intelligence.
*	**The Brain (Elasticsearch/Python):** Acts as the decision-maker, analyzing the severity of alerts and identifying the attacker's unique signature (Source IP).
*	**The Enforcement (UFW/Paramiko):** Acts as the muscle, remotely executing security protocols to sever the connection with the malicious host.

## The Problem vs. The Solution
*	**The Problem:** Traditional security systems notify an administrator via email or dashboard, but by the time a human logs in to manually block the IP, the attacker may have already exfiltrated data or compromised the server.
*	**The Solution:** This project creates a reflexive security loop. Within 5 seconds of an attack starting, the system has detected, notified, and closed the firewall port against that specific attacker, effectively "self-healing" the network boundary.

## Technical Objective
The primary objective of this project is to demonstrate the power of SOAR (Security Orchestration, Automation, and Response) by automating the transition from a "Passive Alert" (knowing you are being attacked) to an "Active Defense" (stopping the attack).

## Technology Stack & Tool Definitions
The system is built on a "Detect, Analyze, Respond" workflow. 
### 1. Detection & Forwarding
These tools reside on the Target Server to monitor traffic and send logs.
*	**Suricata (IDS/IPS):** A high-performance Network Intrusion Detection System. It inspects every packet entering the server and compares it against a "signature" database (rules). If a match is found (like a Ping or an Nmap scan), it logs a JSON-formatted alert.
*	**Filebeat (Log Shipper):** A lightweight shipper for forwarding and centralizing log data. It "watches" Suricata's eve.json alert files and sends new entries to the Brain server in real-time.
*	**UFW (Uncomplicated Firewall):** The interface for managing iptables rules. In this project, UFW acts as our "Enforcement Officer"—it is the tool that actually blocks the attacker's IP once detected.

### 2. Ingestion & Analysis
These tools reside on the HTDRS Brain to store and visualize data.
*	**Elasticsearch (The Database):** A distributed, search and analytics engine. It serves as the central repository where all security alerts are stored, indexed, and made searchable for the SOAR script.
*	**Logstash (The Processor):** A data processing pipeline that ingests data from Filebeat, transforms it (extracting specific fields), and sends it to multiple destinations like Elasticsearch and Email.
*	**Kibana (The Visualization Layer):** A dashboard for Elasticsearch. It allows you to create charts, graphs, and maps to visualize attack trends and high-frequency attacker IPs.

### 3. Automation & Communication	
These tools allow the system to talk to the Target server and the Admin.
*	**Python SOAR Script:** The "Brain" of the response. It continuously monitors Elasticsearch for new alerts and triggers the mitigation logic.
*	**Paramiko:** A Python library used to establish secure SSH connections. It allows our SOAR script to "log in" to the Target server remotely to execute the ufw block command.

## Pre-requirements


To build this system, you need a virtualization environment that can handle three simultaneous operating systems communicating over a private virtual network

### 1.	Hardware Requirements (Host Machine)

Running three VMs requires significant RAM and CPU cores.
*	**Processor:** Minimum 4 Cores (Intel i5/i7 or AMD Ryzen 5/7).
*	**RAM:** Minimum 16GB.
*	**Storage:** 100GB of free space (Preferably SSD for ELK stack performance).

### 2.	Software & Operating Systems

* **Virtualization:** VMware Workstation
* **Attacker:**          Kali Linux
* **SOAR TDRS:**           Ubuntu Server
* **Target:**             Ubuntu Server

The SOAR TDRS requires at least 6GB of RAM because the ELK Stack (Elasticsearch and Logstash) is Java-based and highly memory-intensive.

### 3.	Network Configuration

To make the detection work, all VMs must be on the same Virtual Subnet.
*	**Network Type:** NAT or Host-Only .
*	**IP Scheme:** Use a static range (e.g., 192.168.107.0/24).

### 4.	VMware Installation Steps

**a)	Download ISOs:**
*	Kali Linux Installer
*	Ubuntu Server 22.04 LTS
  
**b)	Create SOAR TDRS VM:**
*	Allocate 60GB Disk (Elasticsearch stores many logs).
*	Install Ubuntu Server
*	Same IP Range
  
**c)	Create Target VM:**
*	Allocate 20GB Disk.
*	Install Ubuntu Server
*	Same IP Range
  
**d)	Create Attacker VM:**
*	Standard Kali installation.



## Target System Implementation

### 1. Initial Hardening & Installation
First, we update the repository and install the core security components.
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y suricata filebeat openssh-server ufw
```
### 2. Network Boundary Configuration (UFW)
We must allow specific traffic so the server doesn't lock us out, and to allow logs to flow to SOAR TDRS.

```bash
sudo ufw allow 22/tcp      
sudo ufw allow 5044/tcp  
sudo ufw enable
```             

### 3. Suricata "Eve-Log" Configuration
Suricata's power comes from its eve.json output, which provides detailed, machine-readable alerts.

**1)	Open Config:** sudo nano /etc/suricata/suricata.yaml

**2)	Set Home Network:** Find HOME_NET and set it to your Target IP: [192.168.107.130/32].

**3)	Set Interface:** Ensure the af-packet section matches your interface name (find it using ip a).

**4)	Enable EVE:** Ensure the outputs section has eve-log set to enabled: yes.

### 4. Filebeat Integration
Filebeat acts as the bridge. We must tell it where to find Suricata logs and where to send them.

**1)	Enable Module:** 
```bash
sudo filebeat modules enable suricata
```
**2)	Configure Output:** Open sudo nano /etc/filebeat/filebeat.yml.
 ```bash
 # output.elasticsearch.
 output.logstash.
Set hosts: ["192.168.107.129:5044"]. Your detection server ip
```
**3)	Start Service:**
```bash
sudo systemctl enable --now filebeat
```
### 5. Automated Response Permission
For the SOAR script on the server to block IPs, it must run “ufw” on this machine. To avoid "Password Required" errors during an attack, we modify the “sudoers” file.
```bash
sudo visudo
ubserver2 ALL=(ALL) NOPASSWD: /usr/sbin/ufw
```
## SOAR TDRS Implementation
### 1. Core Stack Installation
the Elastic Stack components.
```bash

sudo apt install -y openjdk-17-jdk

wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-7.x.list

sudo apt update

sudo apt install -y elasticsearch kibana logstash suricata filebeat
```
### 2. Service Configuration (Network Binding)
To allow communication between the Target and the SOAR TDRS
* **Elasticsearch Configuration:** Open /etc/elasticsearch/elasticsearch.yml.
```bash
#Set
network.host: 0.0.0.0 
discovery.type: single-node
```
*	**Kibana Configuration:** Open /etc/kibana/kibana.yml.
```bash
#Set
server.host: "0.0.0.0" 
```
### 3. Logstash Pipeline Setup
We create a configuration file to define how data flows into the system.
**1.	Create Config:** sudo nano /etc/logstash/conf.d/suricata-elk.conf
**2.	Paste Pipeline Logic:**
```bash
Ruby
input {
  beats { 
    port => 5044 
    host => "0.0.0.0" 
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "suricata-%{+YYYY.MM.dd}"
  }
}
```
### 4. SOAR Automation Script Deployment
Place the soar_automation.py script on your desktop. This script uses Paramiko for SSH and the Elasticsearch Python client to monitor the SIEM.
```bash
pip install elasticsearch paramiko
```
*	It polls Elasticsearch every 5 seconds for new alerts where event_type is alert. When found, it extracts the src_ip and sends a ufw deny command to the Target Server IP (192.168.107.130).
### 5. Email Alerting Setup
To receive instant notifications, ensure the Logstash email plugin is installed and configured with your Gmail App Password.
```bash
sudo /usr/share/logstash/bin/logstash-plugin install logstash-output-email
```
## The Response & Notification Layer
This phase focuses on the Logstash Pipeline (which handles both database storage and immediate email alerting) and the Python SOAR Script (which handles the automated firewall blocking).

### 1. Unified Logstash Pipeline (/etc/logstash/conf.d/suricata-elk.conf)
This configuration ensures that every alert is simultaneously saved to the database and sent to your inbox.
```Ruby
input {
  beats { 
    port => 5044 
    host => "0.0.0.0" 
  }
}

output {
  
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "suricata-%{+YYYY.MM.dd}"
  }

    if [event_type] == "alert" {
    email {
      to => "your-admin-email@gmail.com"
      from => "soar-alerts@SOAR TDRS.com"
      subject => "SOAR TDRS Alert: %{[alert][signature]}"
      body => "Attack Detected!\n\nSource IP: %{[src_ip]}\nTarget IP: %{[dest_ip]}\nAlert Type: %{[alert][signature]}"
      address => "smtp.gmail.com"
      port => 587
      use_tls => true
      username => "your-gmail@gmail.com"
      password => "your-16-digit-app-password"
    }
  }
}
```
### 2. Full SOAR Automation Code (soar_automation.py)
This is the complete, robust version of your code. It handles the SSH connection, executes the block, logs errors to the console, and sends a secondary confirmation email.
```Python
import time
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import paramiko
from elasticsearch import Elasticsearch
from datetime import datetime, timezone

# --- CONFIGURATION ---
ELASTIC_HOST = '127.0.0.1'
TARGET_IP = '192.168.107.130'
TARGET_USER = 'ubserver2'
TARGET_PASS = 'password'

# Email configuration
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SMTP_USER = 'your_email@gmail.com'
SMTP_PASS = 'abcd-efgh-ijkl-mnop' # Your 16-digit App Password
ALERT_RECIPIENT = 'your_email@gmail.com'
ALERT_SENDER = 'soar@SOAR TDRS.com'

es = Elasticsearch([{'host': ELASTIC_HOST, 'port': 9200, 'scheme': 'http'}])

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

WHITELIST = {"192.168.107.129", "192.168.107.130"}

def send_email_alert(attacker_ip):
    """Send an email alert for blocked IP."""
    try:
        msg = MIMEMultipart()
        msg['From'] = ALERT_SENDER
        msg['To'] = ALERT_RECIPIENT
        msg['Subject'] = f"SOAR Action: IP {attacker_ip} Blocked"

        body = f"The IP address {attacker_ip} has been automatically blocked by the SOAR TDRS SOAR script.\nActivity detected: Suricata Alert."
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(ALERT_SENDER, ALERT_RECIPIENT, msg.as_string())
        server.quit()
        logging.info(f"Email alert sent for blocked IP: {attacker_ip}")
    except Exception as e:
        logging.error(f"Failed to send email alert: {e}")

def block_ip(attacker_ip):
    """Block the IP using UFW via SSH and send email alert."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(TARGET_IP, username=TARGET_USER, password=TARGET_PASS)
        
        cmd = f"echo {TARGET_PASS} | sudo -S /usr/sbin/ufw insert 1 deny from {attacker_ip}"
        stdin, stdout, stderr = client.exec_command(cmd)
        
        error = stderr.read().decode()
        if error and "sudo: a password is required" not in error: # Filter known sudo echo msg
            logging.error(f"Error blocking IP {attacker_ip}: {error}")
        else:
            logging.info(f" [SOAR] SUCCESS: {attacker_ip} blocked on Target firewall.")
            send_email_alert(attacker_ip)
    except Exception as e:
        logging.error(f"SSH connection failed for IP {attacker_ip}: {e}")
    finally:
        client.close()

def monitor():
    """Monitor Elasticsearch for new Suricata alerts and block IPs."""
    logging.info("SOAR TDRS Active... Monitoring SIEM for malicious activity.")
    handled = set()
    last_timestamp = datetime.now(timezone.utc).isoformat()

    while True:
        try:
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"match": {"event_type": "alert"}},
                            {"range": {"@timestamp": {"gt": last_timestamp}}}
                        ]
                    }
                },
                "size": 100,
                "sort": [{"@timestamp": {"order": "asc"}}]
            }
            res = es.search(index="suricata-*", body=query)
            hits = res['hits']['hits']
            
            if hits:
                for hit in hits:
                    ip = hit['_source'].get('src_ip')
                    timestamp = hit['_source']['@timestamp']
                    if ip and ip not in WHITELIST and ip not in handled:
                        block_ip(ip)
                        handled.add(ip)
                # Update timestamp to avoid re-processing
                last_timestamp = hits[-1]['_source']['@timestamp']
        except Exception as e:
            logging.error(f"Elasticsearch query failed: {e}")
        time.sleep(5)

if __name__ == "__main__":
    monitor()
```
## Execution Sequence
Follow these steps to demonstrate the SOAR Threat Detection & Response system in action.
### Step 1: Initialize the SOAR TDRS 
Start the "intelligence" of your system. This script polls the ELK stack for new security events.
*	**Action:** Open a terminal on the SOAR Server (.129).
*	**Command:** python3 soar_automation.py
*	**Indicator:** The terminal will display:SOAR Active... Monitoring SIEM.

### Step 2: Set up Live Monitoring on the Target
Set up a real-time monitor of the firewall to watch the block happen instantly.
*	**Action:** Open a terminal on the Target Server (.130).
*	**Command:** watch -n 1 sudo ufw status numbered
*	**Indicator:** You will see the current rules (likely just SSH/22). The screen will refresh every second.

### Step 3: Launch the Attack from Kali
Trigger the Suricata detection rules.
*	**Action:** Open a terminal on Kali Linux (.131).
*	**Command (Ping Attack):** ping 192.168.107.130
*	**Command (Reconnaissance Scan):** nmap -A 192.168.107.130

## The Result: Automated Response Chain
Once the attack starts, the system follows this automated workflow:

**1.	Detection:** Suricata on the Target sees the malicious traffic and writes an alert to eve.json.

**2.	Ingestion:** Filebeat picks up the log and sends it to Logstash; Logstash indexes it into Elasticsearch.

**3.	Notification:** Logstash sends an immediate email alert to the administrator.

**4.	Analysis:** The Python SOAR script detects the new entry in Elasticsearch and identifies the Kali IP (192.168.107.131).

**5.	Mitigation:** The Python script establishes an SSH connection to the Target and injects a DENY rule at the top of the firewall.

**6.	Confirmation:**

*	**On SOAR TDRS :** The script prints [SOAR] BLOCKED: 192.168.107.131.

*	**On Target Server:** The watch screen suddenly shows a new DENY rule for the Kali IP.
*	**On Kali Linux:** The ping or nmap output will stop and show Destination Host Prohibited or timeout.

