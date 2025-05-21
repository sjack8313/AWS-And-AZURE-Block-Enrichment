import requests                # Used to call external APIs like VirusTotal
import boto3                   # AWS SDK – used to create NACL rules

# === Replace with your VirusTotal API key ===
vt_key = "REPLACE_VT_API"      #  Replace this with my actual VirusTotal API key whihc i am not sharing here

# Main function to enrich IP and block if malicious
def auto_block_ip(ip, provider="aws"):  # Function that takes an IP and cloud provider ("aws" by default)

    # Step 1: Enrich IP using VirusTotal
    vt = requests.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",  # VT IP enrichment endpoint
        headers={"x-apikey": vt_key}                             # Auth header with your API key
    ).json()

    # Step 2: Extract malicious score from VT response
    vt_score = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
    print(f"[Enrichment] IP: {ip} → VirusTotal Score: {vt_score}")  # Log the enrichment result

    # Step 3: Check if score meets threshold to trigger block
    if vt_score < 5:
        print("[INFO] IP below malicious threshold. No action taken.")
        return  # Exit if score isn't high enough

    # Step 4: If provider is AWS, proceed with NACL block
    if provider == "aws":
        print("[ACTION] Blocking in AWS NACL...")
        ec2 = boto3.client("ec2")  # Assumes AWS credentials or IAM role is configured

        # Create a deny rule for this IP in the NACL
        ec2.create_network_acl_entry(
            NetworkAclId="REPLACE_AWS_NACL_ID",  # Replace with your actual AWS Network ACL ID (e.g., acl-123abc)
            RuleNumber=123,                      #  Pick a unique rule number (1–32766)
            Protocol="-1",                       # -1 = all protocols (TCP, UDP, etc.)
            RuleAction="deny",                   # Deny/block the traffic
            Egress=False,                        # Only affects inbound traffic
            CidrBlock=f"{ip}/32"                 # /32 = block just this one IP
        )

        print(f"[SUCCESS] IP {ip} blocked in AWS NACL.")  # Confirm success


# auto_block_ip("203.0.113.77", provider="aws")  #  Replace with a test IP for development
