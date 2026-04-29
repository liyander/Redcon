import requests
import json
import socket

class SubfinderEnumerator:
    def __init__(self, target):
        self.target = target

    def enumerate(self):
        """
        Enumerate subdomains using crt.sh
        """
        subdomains = set()
        
        try:
            # Query crt.sh
            url = f"https://crt.sh/?q=%25.{self.target}&output=json"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    if name:
                        for n in name.split('\n'):
                            n = n.strip().lower()
                            if not n.startswith('*.'):
                                subdomains.add(n)
        except Exception:
            pass

        return sorted(list(subdomains))
