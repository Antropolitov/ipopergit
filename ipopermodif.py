import requests
import json
import socket
from ipwhois import IPWhois
import time
import concurrent.futures
import nmap
import dns.resolver
from mac_vendor_lookup import MacLookup
from wakeonlan import send_magic_packet
import netifaces

class IPInvestigator:
    def __init__(self, ip_address):
        self.ip = ip_address
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        self.timeout = 10
        self.delay = 1
        self.geo_services = [
            {'url': 'https://ipapi.co/{ip}/json/', 'name': 'ipapi'},
            {'url': 'https://ipinfo.io/{ip}/json', 'name': 'ipinfo', 'token': 'YOUR_TOKEN_HERE'},
            {'url': 'http://ip-api.com/json/{ip}', 'name': 'ip-api'},
            {'url': 'https://geolocation-db.com/json/{ip}', 'name': 'geolocation-db'}
        ]
        self.nm = nmap.PortScanner()

    def validate_ip(self):
        """Расширенная проверка IP-адреса с определением типа"""
        try:
            socket.inet_aton(self.ip)
            
            # Проверка приватных диапазонов
            if any([
                self.ip.startswith('10.'),
                self.ip.startswith('192.168.'),
                self.ip.startswith('172.') and 16 <= int(self.ip.split('.')[1]) <= 31,
                self.ip.startswith('169.254.'),
                self.ip == '127.0.0.1',
                self.ip.startswith('100.64.') and int(self.ip.split('.')[1]) <= 127
            ]):
                return "private"
            return "public"
        except socket.error:
            return "invalid"

    def get_local_network_info(self):
        """Получение информации о локальной сети"""
        try:
            interfaces = netifaces.interfaces()
            net_info = {}
            
            for iface in interfaces:
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for addr_info in addrs[netifaces.AF_INET]:
                        if addr_info['addr'] != '127.0.0.1':
                            net_info[iface] = {
                                'IP': addr_info['addr'],
                                'Netmask': addr_info['netmask'],
                                'Broadcast': addr_info.get('broadcast', 'N/A')
                            }
                            if netifaces.AF_LINK in addrs:
                                net_info[iface]['MAC'] = addrs[netifaces.AF_LINK][0]['addr']
            return net_info
        except Exception as e:
            return {'local_network_error': str(e)}

    def get_device_info(self):
        """Глубокий анализ устройства для приватных IP"""
        try:
            result = {
                'Тип': 'Локальное устройство',
                'Имя хоста': 'Не определено',
                'MAC-адрес': 'Не определено',
                'Производитель': 'Не определено',
                'Открытые порты': [],
                'Предполагаемая ОС': 'Неизвестно'
            }

            # Получение имени хоста
            try:
                hostname = socket.gethostbyaddr(self.ip)[0]
                result['Имя хоста'] = hostname
            except:
                pass

            # Получение MAC-адреса (только в локальной сети)
            try:
                if self.ip.startswith(('192.168.', '10.')):
                    arp_request = f"arp -a {self.ip}"
                    mac = os.popen(arp_request).read().split()[3]
                    if mac:
                        result['MAC-адрес'] = mac
                        try:
                            result['Производитель'] = MacLookup().lookup(mac)
                        except:
                            pass
            except:
                pass

            # Сканирование портов
            try:
                self.nm.scan(self.ip, arguments='-T4 -F')
                if self.ip in self.nm.all_hosts():
                    result['Открытые порты'] = [
                        f"{port} ({self.nm[self.ip]['tcp'][port]['name']})" 
                        for port in self.nm[self.ip]['tcp'] 
                        if self.nm[self.ip]['tcp'][port]['state'] == 'open'
                    ]
                    
                    # Определение ОС по отпечаткам
                    if 'osclass' in self.nm[self.ip]:
                        os_info = self.nm[self.ip]['osclass'][0]
                        result['Предполагаемая ОС'] = f"{os_info['osfamily']} (точность: {os_info['accuracy']}%)"
            except:
                pass

            return result
        except Exception as e:
            return {'device_error': str(e)}

    def scan_ports_advanced(self, ports=None):
        """Продвинутое сканирование портов с многопоточностью"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        
        open_ports = []
        port_services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            135: 'MS RPC',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            993: 'IMAPS',
            995: 'POP3S',
            1723: 'PPTP',
            3306: 'MySQL',
            3389: 'RDP',
            5900: 'VNC',
            8080: 'HTTP-Alt'
        }

        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.ip, port))
                sock.close()
                return port if result == 0 else None
            except:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {executor.submit(check_port, port): port for port in ports}
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    if future.result():
                        service = port_services.get(port, 'Unknown')
                        open_ports.append(f"{port} ({service})")
                except:
                    pass

        return open_ports

    def get_geolocation(self):
        """Улучшенное определение геолокации с несколькими сервисами"""
        results = {}
        
        def fetch_geo(service):
            try:
                url = service['url'].format(ip=self.ip)
                if 'token' in service:
                    url += f"?token={service['token']}"
                
                response = requests.get(url, headers=self.headers, timeout=self.timeout)
                data = response.json()
                
                if service['name'] == 'ipapi' and 'error' not in data:
                    return {
                        'service': 'ipapi.co',
                        'coordinates': f"{data.get('latitude')}, {data.get('longitude')}",
                        'accuracy': data.get('accuracy', 'N/A'),
                        'map': f"https://www.google.com/maps?q={data.get('latitude')},{data.get('longitude')}",
                        'address': data.get('city', '') + ', ' + data.get('region', '') + ', ' + data.get('country_name', '')
                    }
                elif service['name'] == 'ipinfo' and 'loc' in data:
                    lat, lon = data['loc'].split(',')
                    return {
                        'service': 'ipinfo.io',
                        'coordinates': data['loc'],
                        'map': f"https://www.google.com/maps?q={lat},{lon}",
                        'address': data.get('city', '') + ', ' + data.get('region', '') + ', ' + data.get('country', '')
                    }
                elif service['name'] == 'ip-api' and data.get('status') == 'success':
                    return {
                        'service': 'ip-api.com',
                        'coordinates': f"{data.get('lat')}, {data.get('lon')}",
                        'map': f"https://www.google.com/maps?q={data.get('lat')},{data.get('lon')}",
                        'address': data.get('city', '') + ', ' + data.get('regionName', '') + ', ' + data.get('country', '')
                    }
                elif service['name'] == 'geolocation-db' and 'latitude' in data:
                    return {
                        'service': 'geolocation-db.com',
                        'coordinates': f"{data.get('latitude')}, {data.get('longitude')}",
                        'map': f"https://www.google.com/maps?q={data.get('latitude')},{data.get('longitude')}",
                        'address': data.get('city', '') + ', ' + data.get('state', '') + ', ' + data.get('country_name', '')
                    }
            except:
                return None
        
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_to_service = {executor.submit(fetch_geo, service): service['name'] for service in self.geo_services}
            for future in concurrent.futures.as_completed(future_to_service):
                service_name = future_to_service[future]
                try:
                    result = future.result()
                    if result:
                        results[service_name] = result
                except:
                    pass
        
        # Выбираем самый точный результат
        if results:
            best_result = max(results.values(), key=lambda x: len(x.get('address', '')))
            results['best_guess'] = best_result
        
        return results if results else {'geolocation_error': 'Не удалось определить местоположение'}

    def get_whois_info(self):
        """Расширенная WHOIS информация"""
        try:
            obj = IPWhois(self.ip)
            whois_data = obj.lookup_rdap()
            
            result = {
                'Сеть': whois_data.get('network', {}).get('cidr', 'N/A'),
                'Описание': whois_data.get('network', {}).get('name', 'N/A'),
                'Дата создания': whois_data.get('network', {}).get('events', [{}])[0].get('timestamp', 'N/A'),
                'Статус': whois_data.get('network', {}).get('status', 'N/A'),
                'Контакты': []
            }
            
            if 'entities' in whois_data:
                for entity in whois_data['entities']:
                    contact = {
                        'Роль': entity.get('roles', ['N/A'])[0],
                        'Название': entity.get('vcardArray', [None, []])[1][0][3] if 'vcardArray' in entity else 'N/A'
                    }
                    result['Контакты'].append(contact)
            
            return result
        except Exception as e:
            return {'whois_error': str(e)}

    def check_security(self):
        """Проверка безопасности и репутации IP"""
        results = {}
        
        # Проверка AbuseIPDB
        try:
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={self.ip}"
            headers = {'Key': 'YOUR_ABUSEIPDB_KEY', 'Accept': 'application/json'}
            response = requests.get(url, headers=headers, timeout=self.timeout)
            data = response.json()
            
            if data.get('data'):
                results['abuseipdb'] = {
                    'Репутация': data['data'].get('abuseConfidenceScore', 'N/A'),
                    'Отчеты': data['data'].get('totalReports', 'N/A'),
                    'Последний отчет': data['data'].get('lastReportedAt', 'N/A'),
                    'ISP': data['data'].get('isp', 'N/A'),
                    'Домен': data['data'].get('domain', 'N/A')
                }
        except:
            pass
        
        # Проверка VirusTotal
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{self.ip}"
            headers = {'x-apikey': 'YOUR_VIRUSTOTAL_KEY'}
            response = requests.get(url, headers=headers, timeout=self.timeout)
            data = response.json()
            
            if 'data' in data and 'attributes' in data['data']:
                stats = data['data']['attributes'].get('last_analysis_stats', {})
                results['virustotal'] = {
                    'Вредоносные': stats.get('malicious', 0),
                    'Подозрительные': stats.get('suspicious', 0),
                    'Безопасные': stats.get('harmless', 0),
                    'Не определено': stats.get('undetected', 0),
                    'Репутация': data['data']['attributes'].get('reputation', 'N/A')
                }
        except:
            pass
        
        return results if results else {'security_error': 'Не удалось проверить репутацию IP'}

    def get_dns_records(self):
        """Получение DNS записей для домена (если IP связан с доменом)"""
        try:
            hostname = socket.gethostbyaddr(self.ip)[0]
            records = {}
            
            # Проверка различных типов DNS записей
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            
            for rtype in record_types:
                try:
                    answers = resolver.resolve(hostname, rtype)
                    records[rtype] = [str(r) for r in answers]
                except:
                    pass
            
            return {'hostname': hostname, 'dns_records': records} if records else {}
        except:
            return {}

    def wake_on_lan(self, mac_address):
        """Функция Wake-on-LAN для локальных устройств"""
        try:
            send_magic_packet(mac_address)
            return {'status': 'success', 'message': f'WOL packet sent to {mac_address}'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def get_ip_info(self):
        """Полный анализ IP-адреса"""
        ip_type = self.validate_ip()
        
        if ip_type == "invalid":
            return {"error": "Неверный формат IP-адреса"}
            
        print(f"\n[🔍] Начинаем анализ IP: {self.ip} ({'приватный' if ip_type == 'private' else 'публичный'})")
        results = {
            'ip': self.ip,
            'type': 'private' if ip_type == 'private' else 'public'
        }
        
        # Для локальных устройств
        if ip_type == "private":
            results.update(self.get_device_info())
            results['open_ports'] = self.scan_ports_advanced()
            results['local_network'] = self.get_local_network_info()
            return results
        
        # Для публичных IP
        print("[+] Получаем базовую информацию...")
        try:
            url = f"http://ip-api.com/json/{self.ip}?fields=status,message,continent,country,regionName,city,district,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            data = response.json()
            
            if data.get('status') == 'success':
                results['basic_info'] = {
                    'Страна': data.get('country'),
                    'Регион': data.get('regionName'),
                    'Город': data.get('city'),
                    'Почтовый индекс': data.get('zip'),
                    'Провайдер': data.get('isp'),
                    'Организация': data.get('org'),
                    'AS номер': data.get('as'),
                    'AS имя': data.get('asname'),
                    'Обратный DNS': data.get('reverse'),
                    'Мобильный': data.get('mobile'),
                    'Прокси/VPN': data.get('proxy') or data.get('hosting'),
                    'Координаты': f"{data.get('lat')}, {data.get('lon')}",
                    'Часовой пояс': data.get('timezone')
                }
        except Exception as e:
            results['basic_info_error'] = str(e)
        
        print("[+] Получаем геолокацию...")
        geo_data = self.get_geolocation()
        if geo_data:
            results['geolocation'] = geo_data
        
        print("[+] Получаем WHOIS данные...")
        whois_data = self.get_whois_info()
        if whois_data:
            results['whois'] = whois_data
        
        print("[+] Проверяем безопасность...")
        security_data = self.check_security()
        if security_data:
            results['security'] = security_data
        
        print("[+] Проверяем DNS записи...")
        dns_data = self.get_dns_records()
        if dns_data:
            results['dns'] = dns_data
        
        print("[+] Сканируем порты...")
        results['open_ports'] = self.scan_ports_advanced()
        
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