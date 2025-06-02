import requests
import json
import socket
from ipwhois import IPWhois
import time

class IPInvestigator:
    def __init__(self, ip_address):
        self.ip = ip_address
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        self.timeout = 10
        self.delay = 2  

    def validate_ip(self):
        """Проверка валидности IP-адреса"""
        try:
            socket.inet_aton(self.ip)
            return True
        except socket.error:
            return False

    def get_ip_info(self):
        """Получение базовой информации об IP"""
        if not self.validate_ip():
            return {"error": "Неверный формат IP-адреса"}

        print(f"\n[🔍] Начинаем анализ IP: {self.ip}")
        results = {}

       
        print("[+] Получаем базовую информацию...")
        try:
            time.sleep(self.delay)
            url = f"http://ip-api.com/json/{self.ip}?fields=status,message,continent,country,regionName,city,district,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            data = response.json()
            
            if data.get('status') == 'success':
                results['ip_api'] = {
                    'Страна': data.get('country'),
                    'Регион': data.get('regionName'),
                    'Город': data.get('city'),
                    'Провайдер': data.get('isp'),
                    'Организация': data.get('org'),
                    'AS номер': data.get('as'),
                    'Прокси/VPN': data.get('proxy') or data.get('hosting'),
                    'Координаты': f"{data.get('lat')}, {data.get('lon')}",
                    'Часовой пояс': data.get('timezone')
                }
        except Exception as e:
            results['ip_api_error'] = str(e)

        
        print("[+] Получаем WHOIS данные...")
        try:
            time.sleep(self.delay)
            obj = IPWhois(self.ip)
            whois_data = obj.lookup_rdap()
            
            results['whois'] = {
                'Сеть': whois_data.get('network', {}).get('cidr'),
                'Описание': whois_data.get('network', {}).get('name'),
                'Контакты': whois_data.get('entities', [])[0] if whois_data.get('entities') else None,
                'Дата создания': whois_data.get('network', {}).get('events', [{}])[0].get('timestamp'),
                'Статус': whois_data.get('network', {}).get('status')
            }
        except Exception as e:
            results['whois_error'] = str(e)

        
        print("[+] Проверяем VPN/Tor...")
        try:
            time.sleep(self.delay)
            url = f"https://ipinfo.io/{self.ip}/json?token=YOUR_IPINFO_TOKEN"  
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            data = response.json()
            
            results['vpn_tor_check'] = {
                'Тип': data.get('privacy', {}).get('vpn') or data.get('privacy', {}).get('tor'),
                'Сервис': data.get('company', {}).get('name'),
                'Прокси': data.get('privacy', {}).get('proxy')
            }
        except Exception as e:
            results['vpn_error'] = str(e)

        
        print("[+] Проверяем исторические данные...")
        try:
            time.sleep(self.delay)
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={self.ip}"
            headers = {
                'Key': 'YOUR_ABUSEIPDB_KEY',  
                'Accept': 'application/json'
            }
            response = requests.get(url, headers=headers, timeout=self.timeout)
            data = response.json()
            
            if data.get('data'):
                results['abuse_info'] = {
                    'Репутация': data['data'].get('abuseConfidenceScore'),
                    'Количество отчетов': data['data'].get('totalReports'),
                    'Последний отчет': data['data'].get('lastReportedAt'),
                    'Домены': data['data'].get('domain')
                }
        except Exception as e:
            results['abuse_error'] = str(e)

        
        print("[+] Проверяем основные порты...")
        try:
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389]
            open_ports = []
            
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
                time.sleep(0.5)
                
            results['open_ports'] = open_ports
        except Exception as e:
            results['ports_error'] = str(e)

        
        filename = f"ip_report_{self.ip.replace('.', '_')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        
        print(f"\n[✓] Отчет сохранен в файл: {filename}")
        return results

if __name__ == "__main__":
    print("""
    ██╗██████╗      ██████╗ ██████╗ ███████╗██████╗ 
    ██║██╔══██╗    ██╔═══██╗██╔══██╗██╔════╝██╔══██╗
    ██║██████╔╝    ██║   ██║██████╔╝█████╗  ██████╔╝
    ██║██╔═══╝     ██║   ██║██╔═══╝ ██╔══╝  ██╔══██╗
    ██║██║         ╚██████╔╝██║     ███████╗██║  ██║
    ╚═╝╚═╝          ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝ OWNER->@rootkitov
    """)
    
    ip = input("Введите IP-адрес для анализа: ").strip()
    investigator = IPInvestigator(ip)
    report = investigator.get_ip_info()
    
    print("\n" + "="*50)
    print("📋 Результаты анализа IP:")
    print(json.dumps(report, ensure_ascii=False, indent=2))