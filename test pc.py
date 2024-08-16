import nmap

def scan_vulnerabilities(target):
    nm = nmap.PortScanner()
    
    # Esegui una scansione di port scanning
    nm.scan(target, arguments='-p-')

    # Identifica servizi con vulnerabilità conosciute
    for host, result in nm.all_hosts().items():
        for proto, ports in result['tcp'].items():
            for port, port_info in ports.items():
                if 'cpe' in port_info:
                    print(f"Host: {host}, Port: {port}, Service: {port_info['cpe']}")

if __name__ == "__main__":
    target_ip = "indirizzo_ip_del_target"
    scan_vulnerabilities(target_ip)
