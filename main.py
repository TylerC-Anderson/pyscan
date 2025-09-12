import argparse
import socket
import sys
import concurrent.futures

def main():

    # ArgParse setup
    parser = argparse.ArgumentParser(
        description="A DIY Scanning tool.",
        epilog="** DON'T _actually_ run this tool against random domains, dummy"
    )

    # arg.target calls IP supplied by user
    parser.add_argument(
        "target",
        help="Target IP address or hostname (e.g. 192.168.1.1, Google.com**)"
    )

    # arg.port calls port range supplied by user
    parser.add_argument(
        "-p", "--port",
        help="Port or port range (e.g. 22, 20-443). Default: all 65,535 TCP Ports",
        default="1-65535"
    )

    parser.add_argument(
        "-w", "--wait",
        help="Time to wait for socket connection in seconds. Default is 0.05s",
        default=0.05
    )

    # Actually parsing the args according to the
    # user's invocation
    args = parser.parse_args()

    try:
        target_ip = socket.gethostbyname(args.target) # DNS resolution
    except socket.gaierror:
        print(f"Error: unable to resolve {args.target}")
        sys.exit(1)

    
    try:
        target_ports = parse_ports(args.port)         # Getting Port if exists
    except ValueError as e:
        print(f"{e}")
        sys.exit(1)

    try:
        wait_time = float(args.wait)
    except ValueError as e:
        print(f"{e}")
        sys.exit(1)

    # Concurrent Futures loop
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        for port in target_ports:
            scans = executor.submit(scan_ip, target_ip, port, wait_time)


    if (len(target_ports) > 1):
        print(f"Scanning Success! Scanned {target_ip} from ports {target_ports.start} through {target_ports.stop-1}")
    
    else:
        print(f"Scanning Success! Scanned {target_ip} @ port {target_ports.start}")

    sys.exit(0)


# Parse ports handles the formatting of the ports supplied by the user
# so long as the ports are in the format of either a range such as 21-445
# OR a single number (80). Enforces lower-higher port numbers, and
# valid port ranges
def parse_ports(port_arg: str):
    if "-" in port_arg:
        parts = port_arg.split("-")
        if len(parts) != 2:
            raise ValueError(f"Invalid port range: {port_arg}")

        port_min, port_max = (int(p) for p in parts)
        
        if not (1 <= port_min <= 65535 and 1 <= port_max <= 65535):
            raise ValueError(f"Port range out of bounds: {port_arg}")

        if (port_min > port_max):
            raise ValueError(f"Invalid port range: {port_arg}")

        return range(port_min, port_max+1)

    else:
        port = int(port_arg)
        if not (1 <= port <= 65535):
            raise ValueError(f"Invalid port number: {port_arg}")
        return range(port, port+1)

def scan_ip(ip_addr: str, port: int, wait_time: float):
    
    # declare the plug
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as plug:
        plug.settimeout(wait_time)        # <-- sets how long to wait in seconds
        # attempt the connection, record the result
        connection = plug.connect_ex((ip_addr, port))

        # 0 indicates a successful connection
        if (connection == 0):
            print(f"{ip_addr} - open port: {port}")

if __name__ == "__main__":
    main()
