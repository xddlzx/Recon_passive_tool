import requests
import dns.resolver
import json
from collections import defaultdict


def get_dns_records(domain):
    record_types = ["A", "AAAA", "MX", "NS", "TXT"]
    results = {}

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            results[record_type] = [str(answer) for answer in answers]
        except Exception:
            results[record_type] = []

    return results


def get_crtsh_subdomains(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = response.json()

        subdomains = set()

        for entry in data:
            names = entry.get("name_value", "").split("\n")
            for name in names:
                clean_name = name.strip().lower()
                if clean_name == domain or clean_name.endswith("." + domain):
                    subdomains.add(clean_name)

        return sorted(subdomains)

    except Exception as error:
        return [f"Could not fetch certificate data: {error}"]


def analyze_dns_security(dns_records):
    notes = []

    txt_records = " ".join(dns_records.get("TXT", [])).lower()

    if "v=spf1" in txt_records:
        notes.append("SPF record found.")
    else:
        notes.append("SPF record not found.")

    if "dmarc" in txt_records:
        notes.append("Possible DMARC-related TXT record found.")
    else:
        notes.append("DMARC record not directly visible in root TXT records. Check _dmarc.domain separately.")

    if dns_records.get("MX"):
        notes.append("MX records found. Mail provider may be identifiable.")

    return notes


def main():
    domain = input("Enter authorized domain: ").strip().lower()

    print("\n[+] Collecting DNS records...")
    dns_records = get_dns_records(domain)

    print("\n[+] Collecting certificate transparency subdomains...")
    subdomains = get_crtsh_subdomains(domain)

    print("\n[+] Creating report data...")
    report = {
        "domain": domain,
        "mitre_mapping": {
            "T1590": "Gather Victim Network Information",
            "T1593": "Search Open Websites/Domains",
            "T1596": "Search Open Technical Databases"
        },
        "dns_records": dns_records,
        "certificate_transparency_subdomains": subdomains[:50],
        "security_notes": analyze_dns_security(dns_records)
    }

    output_file = f"{domain}_recon_report.json"

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print(f"\n[+] Report saved as {output_file}")


if __name__ == "__main__":
    main()