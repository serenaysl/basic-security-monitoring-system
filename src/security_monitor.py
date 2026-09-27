import csv
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

NETWORK_FILE = BASE_DIR / "data" / "network_events.csv"
SERVICES_FILE = BASE_DIR / "data" / "services.csv"
OUTPUT_FILE = BASE_DIR / "output" / "alerts.csv"

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_MINUTES = 5

PORT_SCAN_THRESHOLD = 8
PORT_SCAN_WINDOW_MINUTES = 1

LARGE_TRAFFIC_THRESHOLD = 1_000_000

INSECURE_SERVICES = {"FTP", "Telnet"}


def load_csv(file_path):
    with file_path.open("r", encoding="utf-8") as file:
        return list(csv.DictReader(file))


def create_alert(alert_type, severity, source, description):
    return {
        "alert_type": alert_type,
        "severity": severity,
        "source": source,
        "description": description,
    }


def detect_brute_force(events):
    alerts = []
    failed_logins = defaultdict(list)

    for event in events:
        if event["event_type"] == "login" and event["status"] == "failed":
            failed_logins[event["source_ip"]].append(
                datetime.fromisoformat(event["timestamp"])
            )

    for source_ip, timestamps in failed_logins.items():
        timestamps.sort()

        for start_index, start_time in enumerate(timestamps):
            end_time = start_time + timedelta(
                minutes=BRUTE_FORCE_WINDOW_MINUTES
            )

            attempts = [
                timestamp
                for timestamp in timestamps[start_index:]
                if timestamp <= end_time
            ]

            if len(attempts) > BRUTE_FORCE_THRESHOLD:
                alerts.append(
                    create_alert(
                        "Brute Force",
                        "High",
                        source_ip,
                        (
                            f"{len(attempts)} failed login attempts "
                            f"within {BRUTE_FORCE_WINDOW_MINUTES} minutes"
                        ),
                    )
                )
                break

    return alerts


def detect_port_scan(events):
    alerts = []
    activity = defaultdict(list)

    for event in events:
        if event["event_type"] == "connection":
            activity[event["source_ip"]].append(
                (
                    datetime.fromisoformat(event["timestamp"]),
                    int(event["destination_port"]),
                )
            )

    for source_ip, connections in activity.items():
        connections.sort()

        for start_index, (start_time, _) in enumerate(connections):
            end_time = start_time + timedelta(
                minutes=PORT_SCAN_WINDOW_MINUTES
            )

            ports = {
                port
                for timestamp, port in connections[start_index:]
                if timestamp <= end_time
            }

            if len(ports) >= PORT_SCAN_THRESHOLD:
                alerts.append(
                    create_alert(
                        "Port Scan",
                        "Medium",
                        source_ip,
                        (
                            f"Connection attempts to {len(ports)} different "
                            f"ports within {PORT_SCAN_WINDOW_MINUTES} minute"
                        ),
                    )
                )
                break

    return alerts


def detect_large_traffic(events):
    alerts = []

    for event in events:
        traffic_bytes = int(event["bytes"])

        if traffic_bytes > LARGE_TRAFFIC_THRESHOLD:
            alerts.append(
                create_alert(
                    "Suspicious Traffic",
                    "Medium",
                    event["source_ip"],
                    (
                        f"Large network event detected: "
                        f"{traffic_bytes} bytes"
                    ),
                )
            )

    return alerts


def detect_insecure_services(services):
    alerts = []

    for service in services:
        if (
            service["status"] == "open"
            and service["service"] in INSECURE_SERVICES
        ):
            alerts.append(
                create_alert(
                    "Potential Vulnerability",
                    "Medium",
                    service["host"],
                    (
                        f"{service['service']} service is open "
                        f"on port {service['port']}"
                    ),
                )
            )

    return alerts


def save_alerts(alerts):
    OUTPUT_FILE.parent.mkdir(exist_ok=True)

    with OUTPUT_FILE.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "alert_type",
                "severity",
                "source",
                "description",
            ],
        )

        writer.writeheader()
        writer.writerows(alerts)


def print_summary(alerts):
    print("\nSecurity Monitoring Summary")
    print("=" * 45)

    if not alerts:
        print("No suspicious activity detected.")
        return

    for alert in alerts:
        print(
            f"[{alert['severity']}] "
            f"{alert['alert_type']} - "
            f"{alert['source']}"
        )
        print(f"  {alert['description']}")

    print("=" * 45)
    print(f"Total alerts: {len(alerts)}")


def main():
    network_events = load_csv(NETWORK_FILE)
    services = load_csv(SERVICES_FILE)

    alerts = []

    alerts.extend(detect_brute_force(network_events))
    alerts.extend(detect_port_scan(network_events))
    alerts.extend(detect_large_traffic(network_events))
    alerts.extend(detect_insecure_services(services))

    save_alerts(alerts)
    print_summary(alerts)

    print(f"\nAlerts saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
