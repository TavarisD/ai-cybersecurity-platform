import re

def extract_iocs(log_text):
    iocs = []

    ip_pattern = r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}"

    ips = re.findall(ip_pattern, log_text)

    for ip in ips:
        iocs.append({
            "indicator_type": "ip_address",
            "indicator_value": ip,
            "ioc_confidence": 95
        })

    return {
        "ioc_count": len(iocs),
        "iocs": iocs
    }