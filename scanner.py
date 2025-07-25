import nmap
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def scan_ports(target, scan_type="normal"):
    """
    Scans the target for open ports and vulnerabilities based on the scan type:
    - normal: Scan ports 1-1024
    - quick: Scan common ports (faster)
    - full: Scan top 1000 ports instead of all ports (faster)
    - vuln: Run specific vulnerability scans based on known Metasploitable 2 services
    """
    nm = nmap.PortScanner()

    logging.info(f"Starting {scan_type} scan on target: {target}")

    try:
        if scan_type == "quick":
            nm.scan(target, arguments='-sV -T5 -F')  # Fast scan
        elif scan_type == "full":
            nm.scan(target, arguments='-sS -T4 --top-ports 1000')  # Full scan on top 1000 ports
        elif scan_type == "vuln":
            # Targeted vulnerability scan for Metasploitable 2
           nm.scan(target, arguments=(
                '--script='
                'ftp-anon,ftp-vsftpd-backdoor,ftp-proftpd-backdoor,'
                'http-slowloris,http-sql-injection,http-dombased-xss,http-enum,http-config-backup,http-robots.txt,'
                'http-methods,http-headers,http-title,http-stored-xss,http-shellshock,http-userdir-enum,'
                'mysql-vuln-cve2012-2122,mysql-empty-password,mysql-info,'
                'smb-vuln-ms08-067,smb-vuln-ms17-010,smb-vuln-cve-2017-7494,smb-enum-shares,smb-enum-users,'
                'sshv1,ssh2-enum-algos,ssh-hostkey,'
                'telnet-brute,telnet-encryption,'
                'rpcinfo,rpc-grind,nfs-showmount,nfs-statfs,'
                'vulners,vulscan,ssl-cert,ssl-enum-ciphers,'
                'dns-zone-transfer,dns-recursion,'
                'snmp-info,snmp-interfaces,snmp-netstat,'
                'smtp-open-relay,smtp-enum-users,'
                'imap-capabilities,pop3-capabilities'
                '--script-timeout=30s -T4 --min-parallelism=100 --min-hostgroup=64'
            ))

        else:
            nm.scan(target, '1-1024', arguments='-T4')  # Normal scan

    except Exception as e:
        logging.error(f"Error scanning {target}: {e}")
        return {}

    open_ports = {}
    for host in nm.all_hosts():
        open_ports[host] = []
        logging.info(f"Host {host} is up. Extracting scan results.")
        
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                state = nm[host][proto][port]['state']
                service = nm[host][proto][port].get('name', 'Unknown service')
                
                if state == 'open':
                    port_info = {'port': port, 'service': service}
                    open_ports[host].append(port_info)
                    
                    logging.info(f"Port {port} ({service}) is open on {host}")

                    # Check for vulnerabilities in the script results
                    if 'script' in nm[host][proto][port]:
                        for script_name, script_output in nm[host][proto][port]['script'].items():
                            logging.info(f"Vulnerability script {script_name} output on port {port}: {script_output}")
                            port_info['vulns'] = port_info.get('vulns', []) + [{script_name: script_output}]
    
    return open_ports
