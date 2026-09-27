import csv
import random
from datetime import datetime, timedelta
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

NETWORK_FILE = DATA_DIR / "network_events.csv"
SERVICES_FILE = DATA_DIR / "services.csv"

random.seed(42)


def generate_network_events():
    events = []
    start_time = datetime(2026, 9, 27, 9, 0, 0)

    # Normal network activity
    normal_ips = [
        "192.168.1.10",
        "192.168.1.11",
        "192.168.1.12",
        "192.168.1.13",
    ]

    normal_ports = [22, 80, 443]

    for i in range(30):
        event_time = start_time + timedelta(minutes=i)

        events.append({
            "timestamp": event_time.isoformat(),
            "source_ip": random.choice(normal_ips),
            "destination_ip": "192.168.1.100",
            "destination_port": random.choice(normal_ports),
            "event_type": "connection",
            "status": "success",
            "bytes": random.randint(500, 50000),
        })

    # Simulated brute-force activity
    attacker_ip = "203.0.113.50"

    for i in range(8):
        event_time = start_time + timedelta(minutes=40, seconds=i * 10)

        events.append({
            "timestamp": event_time.isoformat(),
            "source_ip": attacker_ip,
            "destination_ip": "192.168.1.100",
            "destination_port": 22,
            "event_type": "login",
            "status": "failed",
            "bytes": random.randint(200, 800),
        })

    # Simulated port scan
    scanner_ip = "198.51.100.23"

    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443]

    for i, port in enumerate(scan_ports):
        event_time = start_time + timedelta(minutes=50, seconds=i * 3)

        events.append({
            "timestamp": event_time.isoformat(),
            "source_ip": scanner_ip,
            "destination_ip": "192.168.1.100",
            "destination_port": port,
            "event_type": "connection",
            "status": "attempt",
            "bytes": random.randint(100, 500),
        })

    # Simulated unusually large traffic event
    events.append({
        "timestamp": (start_time + timedelta(minutes=60)).isoformat(),
        "source_ip": "192.168.1.25",
        "destination_ip": "192.168.1.100",
        "destination_port": 443,
        "event_type": "connection",
        "status": "success",
        "bytes": 5000000,
    })

    with NETWORK_FILE.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "timestamp",
                "source_ip",
                "destination_ip",
                "destination_port",
                "event_type",
                "status",
                "bytes",
            ],
        )

        writer.writeheader()
        writer.writerows(events)

    print(f"Created {NETWORK_FILE}")
    print(f"Generated {len(events)} network events.")


def generate_service_data():
    services = [
        {
            "host": "192.168.1.100",
            "port": 22,
            "service": "SSH",
            "status": "open",
        },
        {
            "host": "192.168.1.100",
            "port": 80,
            "service": "HTTP",
            "status": "open",
        },
        {
            "host": "192.168.1.100",
            "port": 21,
            "service": "FTP",
            "status": "open",
        },
        {
            "host": "192.168.1.100",
            "port": 23,
            "service": "Telnet",
            "status": "open",
        },
        {
            "host": "192.168.1.100",
            "port": 443,
            "service": "HTTPS",
            "status": "open",
        },
    ]

    with SERVICES_FILE.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=["host", "port", "service", "status"],
        )

        writer.writeheader()
        writer.writerows(services)

    print(f"Created {SERVICES_FILE}")
    print(f"Generated {len(services)} service records.")


def main():
    DATA_DIR.mkdir(exist_ok=True)

    generate_network_events()
    generate_service_data()


if __name__ == "__main__":
    main()
