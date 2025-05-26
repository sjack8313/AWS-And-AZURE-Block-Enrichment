import requests                # Used to call external APIs like VirusTotal
import boto3                   # AWS SDK – used to create NACL rules

# === Replace with your VirusTotal API key ===
vt_key = "REPLACE_VT_API"      #  Replace this with my actual VirusTotal API key whihc i am not sharing here

## ✅ AWS IP Block Automation via Network ACL (NACL)
# Description:
# This script adds a deny rule to an AWS NACL to block a suspicious IP address.
# Use in SOAR or IR pipelines when triaging threats from VPC logs, GuardDuty, etc.

import boto3

# --- 🔁 Replace these with your actual environment settings ---
ip_to_block = "195.51.100.0"           # 🔁 IP to block (IPv4)
region = "us-east-1"                   # 🔁 Your AWS region
nacl_id = "acl-xxxxxxxxxxxxxxxxx"      # 🔁 Your NACL ID (must exist)
rule_number = 300                      # 🔁 Rule number (must be unique and unused)
direction = "ingress"                  # Can be "ingress" or "egress" depending on threat flow

# --- Connect to EC2 (required for NACL management) ---
ec2 = boto3.client("ec2", region_name=region)

# --- Build the NACL rule payload ---
entry = {
    "NetworkAclId": nacl_id,
    "RuleNumber": rule_number,
    "Protocol": "-1",  # -1 = all protocols
    "RuleAction": "deny",
    "Egress": direction == "egress",  # True = outbound rule
    "CidrBlock": f"{ip_to_block}/32",  # Block a single IP
    "PortRange": {
        "From": 0,
        "To": 65535
    }
}

# --- Apply the NACL rule to block the IP ---
try:
    ec2.create_network_acl_entry(**entry)
    print(f"✅ Successfully blocked IP {ip_to_block} in NACL {nacl_id}")
except Exception as e:
    print(f"❌ Failed to block IP: {e}")

