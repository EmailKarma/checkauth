import dns.resolver
import sys

def get_txt_record(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        return [r.to_text().strip('"') for r in answers]
    except Exception as e:
        return []

def check_spf(domain):
    txt_records = get_txt_record(domain)
    for record in txt_records:
        if record.startswith('v=spf'):
            return record
    return 'No SPF record found.'

def check_dmarc(domain):
    dmarc_domain = f'_dmarc.{domain}'
    txt_records = get_txt_record(dmarc_domain)
    for record in txt_records:
        if record.startswith('v=DMARC1'):
            return record
    return 'No DMARC record found.'

def detect_dkim_selectors(domain, selectors=None):
    if selectors is None:
        # You can expand this list or dynamically detect with logs/email headers if available
        selectors = ['default', 'selector1', 'selector2', 'google', 'smtp', 'mail', 'm1', 'k1', 'k2', 'k3', 'hs1', 'dkim1024', 'ctct1', 'k', 's1', '200608', 'sailthru', 'mg', 'dkim']
    
    found = {}
    for selector in selectors:
        dkim_domain = f'{selector}._domainkey.{domain}'
        txt_records = get_txt_record(dkim_domain)
        for record in txt_records:
            if record.startswith('v=DKIM1'):
                found[selector] = record
    return found if found else 'No DKIM records found for known selectors.'

def main(domain):
    print(f"Checking authentication for domain: {domain}\n")
    
    print("SPF:")
    print(check_spf(domain), "\n")
    
    print("DMARC:")
    print(check_dmarc(domain), "\n")

    print("DKIM:")
    dkim_result = detect_dkim_selectors(domain)
    if isinstance(dkim_result, dict):
        for selector, record in dkim_result.items():
            print(f"Selector '{selector}': {record}")
    else:
        print(dkim_result)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python check_auth.py yourdomain.com")
    else:
        main(sys.argv[1])