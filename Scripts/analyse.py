import os
import re
import requests
import email
import pandas as pd
from email import policy
from email.parser import BytesParser
from dotenv import load_dotenv

def extract_email_metadata(file_path):
    with open(file_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    headers = "\n".join(f"{k}: {v}" for k, v in msg.items())

    # Step 1: Reverse Received headers for earliest IP
    received_headers = re.findall(r"^Received:.*$", headers, flags=re.MULTILINE)
    received_headers.reverse()

    for line in received_headers:
        ip_match = re.search(r'[\[\(\<]?(\b(?:\d{1,3}\.){3}\d{1,3}\b)[\]\)\>]?.*', line)
        if ip_match:
            return {
                "file": os.path.basename(file_path),
                "from": msg.get('From', ''),
                "subject": msg.get('Subject', ''),
                "originating_ip": ip_match.group(1)
            }

    # Step 2: Try X-* fallback headers
    fallback_headers = [
        msg.get('X-Originating-IP', ''),
        msg.get('X-Mailgun-Sending-Ip', ''),
        msg.get('X-Sender-IP', ''),
        msg.get('X-Client-IP', ''),
        msg.get('X-Real-IP', '')
    ]
    for val in fallback_headers:
        ip_match = re.search(r'(\b(?:\d{1,3}\.){3}\d{1,3}\b)', val)
        if ip_match:
            return {
                "file": os.path.basename(file_path),
                "from": msg.get('From', ''),
                "subject": msg.get('Subject', ''),
                "originating_ip": ip_match.group(1)
            }

    # Step 3: Regex fallback on full header
    ip_match = re.search(r'(\b(?:\d{1,3}\.){3}\d{1,3}\b)', headers)
    if ip_match:
        return {
            "file": os.path.basename(file_path),
            "from": msg.get('From', ''),
            "subject": msg.get('Subject', ''),
            "originating_ip": ip_match.group(1)
        }

    # Step 4: If still no IP found, return default message
    return {
        "file": os.path.basename(file_path),
        "from": msg.get('From', ''),
        "subject": msg.get('Subject', ''),
        "originating_ip": "IP not found (possibly internal or calendar email)"
    }


def geolocate_ip(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        return {
            "ip": ip,
            "country": data.get('country', 'N/A'),
            "org": data.get('org', 'N/A'),
            "region": data.get('regionName', 'N/A')
        }
    except:
        return {"ip": ip, "country": "N/A", "org": "N/A", "region": "N/A"}

def virustotal_lookup(ip, api_key):
    headers = {"x-apikey": api_key}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    try:
        response = requests.get(url, headers=headers)
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        return {
            "vt_malicious": stats.get('malicious', 0),
            "vt_suspicious": stats.get('suspicious', 0),
            "vt_undetected": stats.get('undetected', 0)
        }
    except:
        return {"vt_malicious": "N/A", "vt_suspicious": "N/A", "vt_undetected": "N/A"}

def process_emails(path, use_virustotal=False, vt_api_key=None):
    all_results = []
    if os.path.isdir(path):
        files = [
            os.path.join(path, f)
            for f in os.listdir(path)
            if os.path.isfile(os.path.join(path, f))
        ]
    else:
        files = [path]

    for file_path in files:
        email_data = extract_email_metadata(file_path)
        ip = email_data['originating_ip']
        if ip and not ip.startswith("IP not found"):
            # Only process if IP is a valid IP address
            geo_info = geolocate_ip(ip)
            vt_info = virustotal_lookup(ip, vt_api_key) if use_virustotal and vt_api_key else {}

            result = {
                "file": email_data['file'],
                "from": email_data['from'],
                "subject": email_data['subject'],
                "ip": ip,
                "country": geo_info['country'],
                "org": geo_info['org'],
                "region": geo_info['region']
            }
            result.update(vt_info)
            all_results.append(result)
        else:
            # For emails without valid IP, still add them with placeholders
            result = {
                "file": email_data['file'],
                "from": email_data['from'],
                "subject": email_data['subject'],
                "ip": None,
                "country": None,
                "org": None,
                "region": None,
                "vt_malicious": None,
                "vt_suspicious": None,
                "vt_undetected": None
            }
            all_results.append(result)

    df = pd.DataFrame(all_results)
    output_path = os.path.join(os.getcwd(), "all_promotionalads_email_trace_results.xlsx")
    df.to_excel(output_path, index=False)
    print(f"Results written to {output_path}")
    return output_path

load_dotenv()  # take environment variables from .env file
vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
result_file = process_emails(r"CategorisedSpamMail\Promotional Ads", use_virustotal=True, vt_api_key=vt_api_key)