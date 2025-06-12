from pip._vendor import requests
import time

def cvePoc(cve):
    url = 'https://cveawg.mitre.org/api/cve/' + str(cve)
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        adp_entries = data.get('containers', {}).get('adp', [])
        for adp_entry in adp_entries:
            metrics = adp_entry.get('metrics', [])
            for metric in metrics:
                other = metric.get('other', {})
                content = other.get('content', {})
                options = content.get('options', [])
                
                for option in options:
                    for key, value in option.items():
                        if key == 'Exploitation':
                            print(f"  {cve}  {value}")
    else:
        print(f"Error: {response.status_code}")
        return None


if __name__ == "__main__":
    alasCVE = ['CVE-2024-26914',	'CVE-2024-26948',	'CVE-2024-35794']   
    for cve in alasCVE:
      cvePoc(cve)
      time.sleep(1)
