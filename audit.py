#!/usr/bin/env python3
"""
Internet Exposure Audit Tool v1.0
Cybersecurity Engineer - Automated Shodan Audit
"""

import shodan
import json
from datetime import datetime
from prettytable import PrettyTable
import folium
import pandas as pd
import os
from typing import Dict, List

# ============ CONFIGURATION ============
# PASTE YOUR SHODAN API KEY BETWEEN THE QUOTES BELOW
SHODAN_API_KEY = "EfoKLcb2zHhNjyxmsIeU95hRHOcLqxb8"  
# =======================================

class ExposureAuditor:
    """Automated Internet Exposure Auditor"""

    HIGH_RISK_PORTS = {
        21: "FTP (Anonymous risk)",
        22: "SSH (Brute-force risk)",
        23: "Telnet (Plaintext risk)",
        3389: "RDP (Attack surface)",
        5900: "VNC (Unauth access risk)",
        27017: "MongoDB (Unauth risk)",
        6379: "Redis (Unauth risk)",
        9200: "Elasticsearch (Data leak)",
        1433: "MSSQL (DB attack)",
        3306: "MySQL (DB attack)",
    }

    def __init__(self, api_key: str):
        self.api = shodan.Shodan(api_key)
        self.results = []
        self.summary = {
            "total_hosts": 0,
            "total_ports": 0,
            "high_risk_ports": 0,
            "vulnerabilities": [],
            "countries": {},
            "organizations": {}
        }

    def search_domain(self, domain: str, limit: int = 100) -> List[Dict]:
        print(f"[*] Searching domain: {domain}")
        try:
            query = f'hostname:{domain}'
            results = self.api.search(query, limit=limit)
            print(f"[+] Found {results['total']} exposed hosts")
            for match in results['matches']:
                host_info = self.get_host_details(match['ip_str'])
                if host_info:
                    self.results.append(host_info)
            return self.results
        except shodan.APIError as e:
            print(f"[!] Shodan API Error: {e}")
            return []

    def get_host_details(self, ip: str) -> Dict:
        try:
            host = self.api.host(ip)
            ports = host.get('ports', [])
            high_risk = [p for p in ports if p in self.HIGH_RISK_PORTS]
            vulns = host.get('vulns', {})
            
            self.summary['total_ports'] += len(ports)
            self.summary['high_risk_ports'] += len(high_risk)
            for v in vulns.keys():
                if v not in self.summary['vulnerabilities']:
                    self.summary['vulnerabilities'].append(v)
            
            country = host.get('country_name', 'Unknown')
            self.summary['countries'][country] = self.summary['countries'].get(country, 0) + 1
            org = host.get('org', 'Unknown')
            self.summary['organizations'][org] = self.summary['organizations'].get(org, 0) + 1

            return {
                'ip': ip,
                'ports': ports,
                'high_risk_ports': high_risk,
                'services': [{
                    'port': s.get('port'),
                    'product': s.get('product', 'Unknown'),
                    'version': s.get('version', ''),
                    'banner': s.get('data', '')[:200]
                } for s in host.get('data', [])],
                'vulnerabilities': list(vulns.keys()),
                'country': country,
                'org': org,
                'os': host.get('os', 'Unknown'),
                'last_update': host.get('last_update', '')
            }
        except shodan.APIError as e:
            print(f"[!] Failed to fetch {ip}: {e}")
            return None

    def generate_report(self, output_dir: str = "./audit_report"):
        os.makedirs(output_dir, exist_ok=True)
        self._print_terminal_report()
        self._save_json_report(output_dir)
        self._generate_map(output_dir)
        self._generate_csv(output_dir)
        print(f"\n[+] All reports saved to: {output_dir}/")

    def _print_terminal_report(self):
        print("\n" + "="*60)
        print("        🌐 INTERNET EXPOSURE AUDIT REPORT")
        print("="*60)
        print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Hosts Found: {len(self.results)}")
        print(f"  Open Ports: {self.summary['total_ports']}")
        print(f"  ⚠️ High-Risk Ports: {self.summary['high_risk_ports']}")
        print(f"  🔴 Vulnerabilities: {len(self.summary['vulnerabilities'])}")
        print("="*60)
        if self.results:
            table = PrettyTable()
            table.field_names = ["IP", "Country", "Open Ports", "High-Risk", "Vulns"]
            for host in self.results[:20]:
                table.add_row([
                    host['ip'], host['country'], 
                    len(host['ports']), 
                    len(host['high_risk_ports']), 
                    len(host['vulnerabilities'])
                ])
            print("\n📋 Asset List (Top 20):")
            print(table)
        print("\n📍 Geographic Distribution:")
        for country, count in sorted(self.summary['countries'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  • {country}: {count} hosts")

    def _save_json_report(self, output_dir: str):
        with open(f"{output_dir}/audit_report.json", 'w') as f:
            json.dump({
                'metadata': {'generated': datetime.now().isoformat(), 'total_hosts': len(self.results)},
                'hosts': self.results,
                'summary': self.summary
            }, f, indent=2, default=str)

    def _generate_map(self, output_dir: str):
        m = folium.Map(location=[20, 0], zoom_start=2)
        folium.Marker(
            location=[20, 0],
            popup=f"Found {len(self.results)} exposed hosts",
            icon=folium.Icon(color='red')
        ).add_to(m)
        m.save(f"{output_dir}/exposure_map.html")
        print(f"[+] Map generated: {output_dir}/exposure_map.html")

    def _generate_csv(self, output_dir: str):
        data = [{
            'IP': h['ip'],
            'Country': h['country'],
            'Org': h['org'],
            'OS': h['os'],
            'Open Ports': len(h['ports']),
            'High-Risk Ports': ', '.join(map(str, h['high_risk_ports'])),
            'Vulnerabilities': ', '.join(h['vulnerabilities'])
        } for h in self.results]
        pd.DataFrame(data).to_csv(f"{output_dir}/audit_report.csv", index=False, encoding='utf-8-sig')
        print(f"[+] CSV generated: {output_dir}/audit_report.csv")

def main():
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║     🔍 Internet Exposure Audit Tool v1.0                ║
    ║     Shodan-powered Attack Surface Mapper                ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    auditor = ExposureAuditor(SHODAN_API_KEY)
    target = input("Enter target domain (e.g., example.com): ").strip()
    if not target:
        print("[!] Invalid input.")
        return
    print(f"\n[+] Auditing: {target}")
    auditor.search_domain(target, limit=50)
    if auditor.results:
        auditor.generate_report()
        print("\n✅ Audit complete!")
    else:
        print("\n[!] No exposed assets found.")

if __name__ == "__main__":
    main()