import nmap

def scan_common_ports(host='127.0.0.1'):
    nm = nmap.PortScanner()
    # Expanded list of common ports as a comma-separated string
    ports = '21,22,25,53,80,110,135,139,143,443,445,3389,3306,8080,8443'
    nm.scan(host, ports)
    open_ports = []
    for proto in nm[host].all_protocols():
        ports = nm[host][proto].keys()
        for port in ports:
            if nm[host][proto][port]['state'] == 'open':
                open_ports.append(f"{proto}/{port}")
    return open_ports


