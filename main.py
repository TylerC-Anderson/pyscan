import argparse
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# Prettifying
from rich import print
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TimeRemainingColumn, TimeElapsedColumn

# tracking progress and context
# import multiprocessing
import datetime

def main():

    # ArgParse setup
    parser = argparse.ArgumentParser(
        description="A DIY Scanning tool.",
        epilog="** DON'T _actually_ run this tool against random domains, dummy")
    # arg.target calls IP supplied by user
    parser.add_argument(
        "target",
        help="Target IP address or hostname (e.g. 192.168.1.1, Google.com**)")
    # arg.port calls port range supplied by user
    parser.add_argument(
        "-p", "--port",
        help="Port or port range (e.g. 22, 20-443). Default: all 65,535 TCP Ports",
        default="1-65535")
    parser.add_argument(
        "-w", "--wait",
        help="Time to wait for socket connection in seconds. Default is 0.05s",
        type=float,
        default=0.05)
    # Actually parsing the args according to the
    # user's invocation
    args = parser.parse_args()

    try:
        target_ip = socket.gethostbyname(args.target) # DNS resolution
    except socket.gaierror:
        print(f"Error: unable to resolve {args.target}")
        sys.exit(2)

    
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

    display_banner(target_ip)

    try:
        process_scan(target_ip, target_ports, wait_time)
    except KeyboardInterrupt:
        print("\nExiting program.")
        sys.exit(-1)
    except socket.error as e:
        print(f"Socket error: {e}")
        sys.exit(2)

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
def scan_port(ip_addr: str, port: int, wait_time: float):
    
    # declare the plug
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as plug:
        plug.settimeout(wait_time)        # <-- sets how long to wait in seconds
        # attempt the connection, record the result
        connection = plug.connect_ex((ip_addr, port))

        # 0 indicates a successful connection
        if (connection == 0):
            print(f"{ip_addr} - open port: {port}")
def display_banner(target_ip: str):
    curr_date_and_time = datetime.datetime.now()
    today = curr_date_and_time.strftime("%x")
    now = curr_date_and_time.strftime("%X")

    border_string = Panel.fit(f"\nPyScan activated. Target IP: {target_ip}\nStarting scan. Scan started on {today} @ {now}\n",
    title="PyScan Port Scanner")

    print()
    print(border_string)
def process_scan(target_ip: str, ports: range, wait_time: float):
    # Code for Tracking progress in a parellelized process is
    # adapted from code courtesy of Dean Montgomery @ URL:
    # https://www.deanmontgomery.com/2022/03/24/rich-progress-and-multiprocessing/
    
    with Progress(
        "[progress.description]{task.description}",
        BarColumn(),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeRemainingColumn(),
        TimeElapsedColumn(),
        ) as progress:
        
        scan_task = progress.add_task(f"[cyan]Progress of ports {ports.start} - {ports.stop-1}: ", total = len(ports))
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []

        # Concurrent Futures loop
            for port in ports:
                future = executor.submit(scan_port, target_ip, port, wait_time)
                futures.append(future)
            
            for future in as_completed(futures):
                if exc := future.exception():
                    pass
                progress.advance(scan_task, 1)           
                future.result()


    if (len(ports) > 1):
        print(f"Scanning Success! Scanned {target_ip} from ports {ports.start} through {ports.stop-1}")
    
    else:
        print(f"Scanning Success! Scanned {target_ip} @ port {ports.start}")

if __name__ == "__main__":
    main()
