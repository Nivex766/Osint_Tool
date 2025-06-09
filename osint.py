import os
import sys
import dns.resolver
import whois
import socket
import requests
from time import sleep
from colorama import Fore, Back, Style, init
import concurrent.futures
import json
from urllib.parse import urlparse

# Inicializa cores (Windows/Linux/Mac)
init(autoreset=True)

# Configurações globais
SERVICES_SUBDOMAINS = [".onrender.com", ".herokuapp.com", ".github.io", ".vercel.app", ".netlify.app"]
DNS_SERVERS = ['8.8.8.8', '1.1.1.1']  # Google DNS e Cloudflare
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 
    80: "HTTP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 8080: "HTTP-Alt"
}

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def display_banner():
    print(Fore.MAGENTA + r"""
  _  _ ____ _  _ _  _ _ ____    ____ _  _ ____ _  _ 
  |\ | |___  \/  |  | | | __    [__  |__| |___ |\ | 
  | \| |___ _/\_ |__| |_|_]___ ___]  |  | |___ | \| 
    """ + Style.RESET_ALL)
    print(Fore.CYAN + "  N1V3X OSINT Tool - by N1vëx" + Style.RESET_ALL)
    print(Fore.YELLOW + "="*60 + Style.RESET_ALL)

def menu():
    print(Fore.GREEN + "\n [MENU PRINCIPAL]" + Style.RESET_ALL)
    print(Fore.CYAN + "  1. 🔍 Consulta DNS Completa")
    print("  2. 🌐 Informações WHOIS (Dono do Domínio)")
    print("  3. 📧 Servidores de E-mail (MX Records)")
    print("  4. 🗺️ Geolocalização do Servidor")
    print("  5. 🚪 Scan de Portas Avançado")
    print("  6. 💻 Verificar Tecnologias do Site")
    print("  7. 🛡️ Verificar Headers de Segurança")
    print("  8. 🕵️‍♂️ TODAS as Opções (Full Scan)")
    print("  9. 🔄 Trocar Alvo")
    print(Fore.RED + "  0. ❌ Sair" + Style.RESET_ALL)
    return input(Fore.YELLOW + "\n  ➤ Selecione uma opção: " + Style.RESET_ALL)
    
def clean_domain(domain):
    """Remove protocolos e paths do domínio"""
    domain = domain.strip()
    for proto in ['https://', 'http://', 'ftp://']:
        if domain.startswith(proto):
            domain = domain[len(proto):]
    return domain.split('/')[0].split('?')[0]

def is_service_subdomain(domain):
    """Verifica se é um subdomínio de serviço"""
    return any(domain.endswith(sd) for sd in SERVICES_SUBDOMAINS)

def dns_lookup(domain):
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = DNS_SERVERS
        
        print(Fore.GREEN + f"\n [DNS LOOKUP]" + Style.RESET_ALL)
        
        # A Records
        print(Fore.CYAN + "\n  🔷 IPv4 (A Records):" + Style.RESET_ALL)
        try:
            a_records = resolver.resolve(domain, 'A')
            for ip in a_records:
                print(f"  → {Fore.YELLOW}{ip}{Style.RESET_ALL}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            print(f"  {Fore.RED}⚠️ Sem registros A encontrados{Style.RESET_ALL}")
        
        # AAAA Records (IPv6)
        print(Fore.CYAN + "\n  🔷 IPv6 (AAAA Records):" + Style.RESET_ALL)
        try:
            aaaa_records = resolver.resolve(domain, 'AAAA')
            for ip in aaaa_records:
                print(f"  → {Fore.YELLOW}{ip}{Style.RESET_ALL}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            print(f"  {Fore.RED}⚠️ Sem registros AAAA encontrados{Style.RESET_ALL}")
        
        # MX Records
        print(Fore.CYAN + "\n  🔷 Servidores de E-mail (MX):" + Style.RESET_ALL)
        try:
            mx_records = resolver.resolve(domain, 'MX')
            for mx in mx_records:
                print(f"  → {Fore.YELLOW}{mx.to_text()}{Style.RESET_ALL}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            print(f"  {Fore.RED}⚠️ Sem registros MX encontrados{Style.RESET_ALL}")
            
        # TXT Records
        print(Fore.CYAN + "\n  🔷 Registros TXT:" + Style.RESET_ALL)
        try:
            txt_records = resolver.resolve(domain, 'TXT')
            for txt in txt_records:
                print(f"  → {Fore.YELLOW}{txt.to_text()}{Style.RESET_ALL}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            print(f"  {Fore.RED}⚠️ Sem registros TXT encontrados{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"  {Fore.RED}❌ Erro DNS: {e}{Style.RESET_ALL}")

def whois_lookup(domain):
    try:
        print(Fore.GREEN + f"\n [WHOIS LOOKUP]" + Style.RESET_ALL)
        
        if is_service_subdomain(domain):
            service = domain.split('.')[-2] + '.' + domain.split('.')[-1]
            print(f"  {Fore.YELLOW}⚠️ Subdomínio de serviço ({service}) - WHOIS não disponível{Style.RESET_ALL}")
            print(f"  → Consulte o painel do {Fore.CYAN}{service}{Style.RESET_ALL} para informações")
            return
        
        w = whois.whois(domain)
        
        if not w.domain_name:
            print(f"  {Fore.RED}❌ Domínio não registrado ou inválido{Style.RESET_ALL}")
            return
            
        print(Fore.CYAN + "\n  🔷 Informações Básicas:" + Style.RESET_ALL)
        print(f"  → Domínio: {Fore.YELLOW}{w.domain_name or 'N/A'}{Style.RESET_ALL}")
        print(f"  → Criado em: {Fore.YELLOW}{w.creation_date or 'N/A'}{Style.RESET_ALL}")
        print(f"  → Expira em: {Fore.YELLOW}{w.expiration_date or 'N/A'}{Style.RESET_ALL}")
        
        print(Fore.CYAN + "\n  🔷 Contato:" + Style.RESET_ALL)
        print(f"  → Registrante: {Fore.YELLOW}{w.name or 'N/A'}{Style.RESET_ALL}")
        print(f"  → Organização: {Fore.YELLOW}{w.org or 'N/A'}{Style.RESET_ALL}")
        print(f"  → País: {Fore.YELLOW}{w.country or 'N/A'}{Style.RESET_ALL}")
        
        print(Fore.CYAN + "\n  🔷 Registrar:" + Style.RESET_ALL)
        print(f"  → WHOIS Server: {Fore.YELLOW}{w.whois_server or 'N/A'}{Style.RESET_ALL}")
        print(f"  → Registrar: {Fore.YELLOW}{w.registrar or 'N/A'}{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"  {Fore.RED}❌ Erro WHOIS: {e}{Style.RESET_ALL}")

def geo_lookup(domain):
    try:
        print(Fore.GREEN + f"\n [GEOLOCATION]" + Style.RESET_ALL)
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = DNS_SERVERS
        
        a_records = resolver.resolve(domain, 'A')
        for ip in a_records:
            try:
                response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query")
                geo = response.json()
                
                if geo.get('status') == 'fail':
                    print(f"  {Fore.RED}❌ Erro: {geo.get('message', 'Unknown error')}{Style.RESET_ALL}")
                    continue
                    
                print(Fore.CYAN + f"\n  🔷 IP: {Fore.YELLOW}{ip}{Style.RESET_ALL}")
                print(f"  → País: {Fore.YELLOW}{geo.get('country', 'N/A')} ({geo.get('countryCode', '')}){Style.RESET_ALL}")
                print(f"  → Região: {Fore.YELLOW}{geo.get('regionName', 'N/A')} ({geo.get('region', '')}){Style.RESET_ALL}")
                print(f"  → Cidade: {Fore.YELLOW}{geo.get('city', 'N/A')}{Style.RESET_ALL}")
                print(f"  → Provedor: {Fore.YELLOW}{geo.get('isp', 'N/A')}{Style.RESET_ALL}")
                print(f"  → ASN: {Fore.YELLOW}{geo.get('as', 'N/A')}{Style.RESET_ALL}")
                print(f"  → Coordenadas: {Fore.YELLOW}{geo.get('lat', 'N/A')}, {geo.get('lon', 'N/A')}{Style.RESET_ALL}")
                
            except requests.exceptions.RequestException as e:
                print(f"  {Fore.RED}❌ Erro ao consultar geolocalização para {ip}: {e}{Style.RESET_ALL}")
                
    except Exception as e:
        print(f"  {Fore.RED}❌ Erro de geolocalização: {e}{Style.RESET_ALL}")

def check_port(ip, port, service):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((str(ip), port))
        sock.close()
        return port, service, result == 0
    except:
        return port, service, False

def port_scan(domain):
    try:
        print(Fore.GREEN + f"\n [PORT SCAN]" + Style.RESET_ALL)
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = DNS_SERVERS
        
        a_records = resolver.resolve(domain, 'A')
        
        for ip in a_records:
            print(Fore.CYAN + f"\n  🔷 Verificando {Fore.YELLOW}{ip}{Style.RESET_ALL}")
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(check_port, ip, port, service) for port, service in COMMON_PORTS.items()]
                
                for future in concurrent.futures.as_completed(futures):
                    port, service, is_open = future.result()
                    if is_open:
                        print(f"  → {Fore.GREEN}✅ Porta {port} ({service}) ABERTA{Style.RESET_ALL}")
                    else:
                        print(f"  → {Fore.RED}❌ Porta {port} ({service}) fechada{Style.RESET_ALL}")
                
    except Exception as e:
        print(f"  {Fore.RED}❌ Erro no scan de portas: {e}{Style.RESET_ALL}")

def check_tech_stack(domain):
    try:
        print(Fore.GREEN + f"\n [TECHNOLOGIES]" + Style.RESET_ALL)
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        try:
            response = requests.get(f"https://{domain}", headers=headers, timeout=10, verify=False)
            server = response.headers.get('Server', 'N/A')
            powered_by = response.headers.get('X-Powered-By', 'N/A')
            
            print(Fore.CYAN + "\n  🔷 Headers:" + Style.RESET_ALL)
            print(f"  → Server: {Fore.YELLOW}{server}{Style.RESET_ALL}")
            print(f"  → X-Powered-By: {Fore.YELLOW}{powered_by}{Style.RESET_ALL}")
            
            # Detect CMS by common patterns
            if 'wp-content' in response.text:
                print(f"  → CMS: {Fore.YELLOW}WordPress detectado{Style.RESET_ALL}")
            elif '/static/js/' in response.text and 'React' in response.text:
                print(f"  → Framework: {Fore.YELLOW}React.js detectado{Style.RESET_ALL}")
                
        except requests.exceptions.SSLError:
            print(f"  {Fore.YELLOW}⚠️ Certificado SSL inválido - tentando HTTP...{Style.RESET_ALL}")
            response = requests.get(f"http://{domain}", headers=headers, timeout=10)
            server = response.headers.get('Server', 'N/A')
            print(f"  → Server (HTTP): {Fore.YELLOW}{server}{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"  {Fore.RED}❌ Erro ao verificar tecnologias: {e}{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"  {Fore.RED}❌ Erro geral: {e}{Style.RESET_ALL}")

def check_security_headers(domain):
    try:
        print(Fore.GREEN + f"\n [SECURITY HEADERS]" + Style.RESET_ALL)
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        try:
            response = requests.get(f"https://{domain}", headers=headers, timeout=10, verify=False)
            
            security_headers = {
                'Strict-Transport-Security': 'HSTS (Força HTTPS)',
                'Content-Security-Policy': 'CSP (Política de Segurança de Conteúdo)',
                'X-Frame-Options': 'Proteção contra clickjacking',
                'X-Content-Type-Options': 'Prevenção de MIME sniffing',
                'Referrer-Policy': 'Política de Referência',
                'Permissions-Policy': 'Política de Permissões',
                'X-XSS-Protection': 'Proteção XSS'
            }
            
            print(Fore.CYAN + "\n  🔷 Cabeçalhos de Segurança:" + Style.RESET_ALL)
            for header, description in security_headers.items():
                value = response.headers.get(header, 'NÃO CONFIGURADO')
                color = Fore.GREEN if value != 'NÃO CONFIGURADO' else Fore.RED
                print(f"  → {description}: {color}{value}{Style.RESET_ALL}")
                
        except requests.exceptions.SSLError:
            print(f"  {Fore.YELLOW}⚠️ Certificado SSL inválido - verificando HTTP...{Style.RESET_ALL}")
            response = requests.get(f"http://{domain}", headers=headers, timeout=10)
            
            for header, description in security_headers.items():
                value = response.headers.get(header, 'NÃO CONFIGURADO')
                color = Fore.GREEN if value != 'NÃO CONFIGURADO' else Fore.RED
                print(f"  → {description} (HTTP): {color}{value}{Style.RESET_ALL}")
                
        except Exception as e:
            print(f"  {Fore.RED}❌ Erro ao verificar cabeçalhos: {e}{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"  {Fore.RED}❌ Erro geral: {e}{Style.RESET_ALL}")

def full_scan(domain):
    print(Fore.MAGENTA + "\n [INICIANDO SCAN COMPLETO]" + Style.RESET_ALL)
    dns_lookup(domain)
    whois_lookup(domain)
    geo_lookup(domain)
    port_scan(domain)
    check_tech_stack(domain)
    check_security_headers(domain)

def main():
    clear_screen()
    display_banner()
    
    try:
        domain = input(Fore.YELLOW + "Digite o domínio (ex: exemplo.com): "+ Style.RESET_ALL)
        domain = clean_domain(domain)
        
        if not domain or '.' not in domain:
            print(Fore.RED + "❌ Domínio inválido!" + Style.RESET_ALL)
            sys.exit(1)
            
        while True:
            clear_screen()
            display_banner()
            print(Fore.CYAN + f"\n  Domínio alvo: {Fore.YELLOW}{domain}{Style.RESET_ALL}")
            
            choice = menu()
            
            if choice == "1":
                dns_lookup(domain)
            elif choice == "2":
                whois_lookup(domain)
            elif choice == "3":
                try:
                    resolver = dns.resolver.Resolver(configure=False)
                    resolver.nameservers = DNS_SERVERS
                    print(Fore.GREEN + f"\n [MX RECORDS]" + Style.RESET_ALL)
                    mx_records = resolver.resolve(domain, 'MX')
                    for mx in mx_records:
                        print(f"  → {Fore.YELLOW}{mx.to_text()}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"  {Fore.RED}❌ Erro MX: {e}{Style.RESET_ALL}")
            elif choice == "4":
                geo_lookup(domain)
            elif choice == "5":
                port_scan(domain)
            elif choice == "6":
                check_tech_stack(domain)
            elif choice == "7":
                check_security_headers(domain)
            elif choice == "8":
                full_scan(domain)
            elif choice == "9":
                # Opção para trocar o alvo
                new_domain = input(Fore.YELLOW + "\nDigite o novo domínio (ex: novo-exemplo.com): "+ Style.RESET_ALL)
                new_domain = clean_domain(new_domain)
                if not new_domain or '.' not in new_domain:
                    print(Fore.RED + "❌ Domínio inválido! Mantendo o anterior." + Style.RESET_ALL)
                    sleep(2)
                else:
                    domain = new_domain
                    print(Fore.GREEN + f"\n  ✅ Alvo alterado para: {domain}" + Style.RESET_ALL)
                    sleep(1)
                continue
            elif choice == "0":
                print(Fore.RED + "\n  Saindo... Até logo! 👋" + Style.RESET_ALL)
                sys.exit()
            else:
                print(Fore.RED + "\n  ❌ Opção inválida!" + Style.RESET_ALL)
            
            input(Fore.YELLOW + "\n  Pressione Enter para continuar..." + Style.RESET_ALL)
            
    except KeyboardInterrupt:
        print(Fore.RED + "\n\n  ❌ Programa interrompido pelo usuário" + Style.RESET_ALL)
        sys.exit()

if __name__ == "__main__":
    main()
