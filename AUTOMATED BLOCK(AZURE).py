
# ✅ SOAR Automation Script: Block Malicious IP Based on Alert
# Use Case: This script is designed to be triggered when an alert fires for a malicious IP and user.
# It sends a request to your firewall or security tool to block the IP, and can notify or ticket if needed.

import requests  # For sending HTTP requests to firewall APIs or SOAR endpoints

# --- 🔁 Replace these with your environment-specific values ---
malicious_ip = "185.100.87.1"               # 🔁 Replace with the detected malicious IP from the alert
malicious_user = "unknown_user@corp.com"    # 🔁 Replace with the user associated with the alert
firewall_api_url = "https://firewall.local/api/block"  # 🔁 Replace with your actual firewall or SOAR API endpoint
api_token = "REPLACE_FIREWALL_API_KEY"       # 🔁 Replace with your real API key or bearer token

# --- Create the JSON payload to send to your firewall ---
payload = {
    "ip": malicious_ip,                     # IP to be blocked
    "user": malicious_user,                 # Optional: included for context
    "action": "block",                     # Action to take (other options might include 'alert', 'quarantine', etc.)
    "reason": "Detected suspicious behavior from Azure sign-in logs"
}

# --- Set up the headers for authentication and content-type ---
headers = {
    "Authorization": f"Bearer {api_token}",  # Bearer token for API authentication
    "Content-Type": "application/json"        # Specifies that we are sending JSON
}

# --- Send the request ---
try:
    response = requests.post(firewall_api_url, json=payload, headers=headers)  # Send the POST request
    if response.status_code == 200:
        print(f"✅ IP {malicious_ip} successfully blocked.")
    else:
        print(f"❌ Error blocking IP: {response.status_code} - {response.text}")
except Exception as e:
    print(f"❌ Exception occurred: {e}")

# --- Notes ---
# - This script should be integrated into a SOAR platform like Splunk SOAR, XSOAR, or used in Lambda/automation pipeline.
# - You can customize it to include Slack notification, ticket creation, or enrichment logic.
