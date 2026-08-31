import socket
import datetime
import re
import json

# ============================================================
# VULNERABILITY SCANNER - MINI PROJECT
# ============================================================

# Common ports and their services
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Proxy"
}

# Example minimum recommended versions.
# These are demonstration rules for the mini-project.
MINIMUM_VERSIONS = {
    "OpenSSH": 8.0,
    "Apache": 2.4,
    "nginx": 1.20,
    "vsftpd": 3.0,
    "MySQL": 8.0
}


# ------------------------------------------------------------
# Resolve hostname
# ------------------------------------------------------------
def resolve_target(target):
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        print("[!] Unable to resolve target.")
        return None


# ------------------------------------------------------------
# Scan a single port
# ------------------------------------------------------------
def scan_port(ip, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        result = sock.connect_ex((ip, port))
        sock.close()

        return result == 0

    except socket.error:
        return False


# ------------------------------------------------------------
# Get service banner
# ------------------------------------------------------------
def get_banner(ip, port, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        sock.connect((ip, port))

        # Send a basic request for HTTP services
        if port in [80, 8080, 8000]:
            request = (
                "HEAD / HTTP/1.0\r\n"
                "Host: " + ip + "\r\n"
                "\r\n"
            )
            sock.send(request.encode())

        try:
            banner = sock.recv(2048).decode(
                errors="ignore"
            ).strip()
        except socket.timeout:
            banner = ""

        sock.close()

        return banner

    except Exception:
        return ""


# ------------------------------------------------------------
# Extract software version from banner
# ------------------------------------------------------------
def detect_version(banner):
    patterns = [
        r"OpenSSH[_\s/-]?(\d+\.\d+)",
        r"Apache[/\s-]?(\d+\.\d+)",
        r"nginx[/\s-]?(\d+\.\d+)",
        r"vsftpd[/\s-]?(\d+\.\d+)",
        r"MySQL[/\s-]?(\d+\.\d+)",
    ]

    for pattern in patterns:
        match = re.search(pattern, banner, re.IGNORECASE)

        if match:
            version = match.group(1)

            for software in MINIMUM_VERSIONS:
                if software.lower() in banner.lower():
                    return software, version

    return None, None


# ------------------------------------------------------------
# Compare software version
# ------------------------------------------------------------
def check_outdated_software(software, version):
    if not software or not version:
        return None

    try:
        current_version = float(version)
        minimum_version = MINIMUM_VERSIONS[software]

        if current_version < minimum_version:
            return {
                "type": "Outdated Software",
                "severity": "Medium",
                "software": software,
                "version": version,
                "message": (
                    f"{software} {version} may be outdated. "
                    f"Consider upgrading to a supported version."
                )
            }

    except ValueError:
        pass

    return None


# ------------------------------------------------------------
# Check for weak configurations
# ------------------------------------------------------------
def check_weak_configuration(port, service, banner):
    vulnerabilities = []

    # Telnet sends credentials/data without modern encryption
    if port == 23:
        vulnerabilities.append({
            "type": "Weak Configuration",
            "severity": "High",
            "port": port,
            "service": service,
            "message": (
                "Telnet is open. Telnet does not provide "
                "secure encrypted communication. Prefer SSH."
            )
        })

    # FTP may transmit credentials without encryption
    elif port == 21:
        vulnerabilities.append({
            "type": "Weak Configuration",
            "severity": "Medium",
            "port": port,
            "service": service,
            "message": (
                "FTP is open. Prefer SFTP or FTPS "
                "for secure file transfer."
            )
        })

    # HTTP does not provide transport encryption
    elif port == 80:
        vulnerabilities.append({
            "type": "Weak Configuration",
            "severity": "Low",
            "port": port,
            "service": service,
            "message": (
                "HTTP is available. If sensitive information "
                "is transmitted, use HTTPS."
            )
        })

    # SMB commonly deserves review
    elif port == 445:
        vulnerabilities.append({
            "type": "Weak Configuration",
            "severity": "Medium",
            "port": port,
            "service": service,
            "message": (
                "SMB is exposed. Verify firewall rules and "
                "disable unnecessary SMB access."
            )
        })

    return vulnerabilities


# ------------------------------------------------------------
# Scan target
# ------------------------------------------------------------
def vulnerability_scan(target, ports):
    ip = resolve_target(target)

    if not ip:
        return None

    print("\n" + "=" * 60)
    print("VULNERABILITY SCANNER")
    print("=" * 60)

    print(f"Target : {target}")
    print(f"IP     : {ip}")

    open_ports = []
    vulnerabilities = []

    print("\n[+] Scanning ports...\n")

    for port in ports:

        print(
            f"[*] Checking port {port:<5}",
            end="\r"
        )

        if scan_port(ip, port):

            service = COMMON_PORTS.get(
                port,
                "Unknown"
            )

            print(
                f"[OPEN] Port {port:<5} "
                f"Service: {service}"
            )

            open_ports.append({
                "port": port,
                "service": service
            })

            # Get service banner
            banner = get_banner(ip, port)

            # Check weak configuration
            weak_config = check_weak_configuration(
                port,
                service,
                banner
            )

            vulnerabilities.extend(
                weak_config
            )

            # Detect software version
            software, version = detect_version(
                banner
            )

            if software and version:

                print(
                    f"       Version detected: "
                    f"{software} {version}"
                )

                outdated = check_outdated_software(
                    software,
                    version
                )

                if outdated:
                    vulnerabilities.append(
                        outdated
                    )

    print("\n[+] Scan completed.")

    return {
        "target": target,
        "ip_address": ip,
        "scan_time": datetime.datetime.now().isoformat(),
        "open_ports": open_ports,
        "vulnerabilities": vulnerabilities
    }


# ------------------------------------------------------------
# Generate text report
# ------------------------------------------------------------
def generate_text_report(results):
    filename = "vulnerability_report.txt"

    with open(filename, "w") as file:

        file.write("=" * 60 + "\n")
        file.write("        VULNERABILITY SCAN REPORT\n")
        file.write("=" * 60 + "\n\n")

        file.write(
            f"Target       : {results['target']}\n"
        )

        file.write(
            f"IP Address   : {results['ip_address']}\n"
        )

        file.write(
            f"Scan Time    : {results['scan_time']}\n\n"
        )

        # Open ports
        file.write("-" * 60 + "\n")
        file.write("OPEN PORTS\n")
        file.write("-" * 60 + "\n")

        if results["open_ports"]:

            for item in results["open_ports"]:

                file.write(
                    f"Port {item['port']} "
                    f"- {item['service']}\n"
                )

        else:
            file.write(
                "No open ports detected.\n"
            )

        # Vulnerabilities
        file.write("\n" + "-" * 60 + "\n")
        file.write("VULNERABILITIES\n")
        file.write("-" * 60 + "\n")

        if results["vulnerabilities"]:

            for number, vuln in enumerate(
                results["vulnerabilities"],
                start=1
            ):

                file.write(
                    f"\n{number}. "
                    f"{vuln['type']}\n"
                )

                file.write(
                    f"Severity: "
                    f"{vuln['severity']}\n"
                )

                file.write(
                    f"Description: "
                    f"{vuln['message']}\n"
                )

        else:
            file.write(
                "No vulnerabilities detected "
                "by the configured checks.\n"
            )

        file.write("\n" + "=" * 60 + "\n")
        file.write("END OF REPORT\n")
        file.write("=" * 60 + "\n")

    return filename


# ------------------------------------------------------------
# Generate JSON report
# ------------------------------------------------------------
def generate_json_report(results):
    filename = "vulnerability_report.json"

    with open(filename, "w") as file:
        json.dump(
            results,
            file,
            indent=4
        )

    return filename


# ------------------------------------------------------------
# Display results
# ------------------------------------------------------------
def display_results(results):

    print("\n" + "=" * 60)
    print("SCAN SUMMARY")
    print("=" * 60)

    print(
        f"Target: {results['target']}"
    )

    print(
        f"IP Address: {results['ip_address']}"
    )

    print(
        f"Open Ports: "
        f"{len(results['open_ports'])}"
    )

    print(
        f"Vulnerabilities: "
        f"{len(results['vulnerabilities'])}"
    )

    if results["vulnerabilities"]:

        print("\nDetected Issues:")

        for vuln in results["vulnerabilities"]:

            print(
                f"\n[{vuln['severity']}] "
                f"{vuln['type']}"
            )

            print(
                f"    {vuln['message']}"
            )

    else:

        print(
            "\nNo issues were detected "
            "by the configured checks."
        )


# ------------------------------------------------------------
# Main program
# ------------------------------------------------------------
def main():

    print("=" * 60)
    print("       VULNERABILITY SCANNER")
    print("              MINI PROJECT")
    print("=" * 60)

    print(
        "\nUse this tool only against systems "
        "you are authorized to test."
    )

    target = input(
        "\nEnter target hostname/IP "
        "(example: 127.0.0.1): "
    ).strip()

    if not target:
        print("[!] Target cannot be empty.")
        return

    # User can choose custom ports
    choice = input(
        "\nScan common ports? (y/n): "
    ).lower()

    if choice == "y":

        ports = list(
            COMMON_PORTS.keys()
        )

    else:

        port_input = input(
            "Enter ports separated by commas "
            "(example: 22,80,443): "
        )

        try:
            ports = [
                int(port.strip())
                for port in port_input.split(",")
            ]

            # Basic validation
            ports = [
                port for port in ports
                if 1 <= port <= 65535
            ]

        except ValueError:

            print(
                "[!] Invalid port numbers."
            )
            return

    # Run scanner
    results = vulnerability_scan(
        target,
        ports
    )

    if not results:
        return

    # Display results
    display_results(results)

    # Generate reports
    text_report = generate_text_report(
        results
    )

    json_report = generate_json_report(
        results
    )

    print("\n" + "=" * 60)
    print("REPORT GENERATED")
    print("=" * 60)

    print(
        f"[+] Text Report : {text_report}"
    )

    print(
        f"[+] JSON Report : {json_report}"
    )


# ------------------------------------------------------------
# Program execution
# ------------------------------------------------------------
if __name__ == "__main__":
    main()