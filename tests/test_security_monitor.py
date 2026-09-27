import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = BASE_DIR / "src"

sys.path.insert(0, str(SRC_DIR))

import security_monitor


class SecurityMonitorTests(unittest.TestCase):

    def test_brute_force_detected(self):
        start_time = datetime(2026, 9, 27, 10, 0, 0)
        events = []

        for i in range(6):
            events.append({
                "timestamp": (
                    start_time + timedelta(seconds=i * 10)
                ).isoformat(),
                "source_ip": "203.0.113.10",
                "destination_ip": "192.168.1.100",
                "destination_port": "22",
                "event_type": "login",
                "status": "failed",
                "bytes": "300",
            })

        alerts = security_monitor.detect_brute_force(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "Brute Force")
        self.assertEqual(alerts[0]["severity"], "High")


    def test_five_failed_logins_do_not_trigger(self):
        start_time = datetime(2026, 9, 27, 10, 0, 0)
        events = []

        for i in range(5):
            events.append({
                "timestamp": (
                    start_time + timedelta(seconds=i * 10)
                ).isoformat(),
                "source_ip": "203.0.113.20",
                "destination_ip": "192.168.1.100",
                "destination_port": "22",
                "event_type": "login",
                "status": "failed",
                "bytes": "300",
            })

        alerts = security_monitor.detect_brute_force(events)

        self.assertEqual(len(alerts), 0)


    def test_port_scan_detected(self):
        start_time = datetime(2026, 9, 27, 11, 0, 0)
        events = []

        ports = [21, 22, 23, 25, 53, 80, 110, 443]

        for i, port in enumerate(ports):
            events.append({
                "timestamp": (
                    start_time + timedelta(seconds=i * 3)
                ).isoformat(),
                "source_ip": "198.51.100.50",
                "destination_ip": "192.168.1.100",
                "destination_port": str(port),
                "event_type": "connection",
                "status": "attempt",
                "bytes": "200",
            })

        alerts = security_monitor.detect_port_scan(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "Port Scan")


    def test_large_traffic_detected(self):
        events = [{
            "timestamp": "2026-09-27T12:00:00",
            "source_ip": "192.168.1.25",
            "destination_ip": "192.168.1.100",
            "destination_port": "443",
            "event_type": "connection",
            "status": "success",
            "bytes": "1000001",
        }]

        alerts = security_monitor.detect_large_traffic(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["alert_type"],
            "Suspicious Traffic"
        )


    def test_insecure_services_detected(self):
        services = [
            {
                "host": "192.168.1.100",
                "port": "21",
                "service": "FTP",
                "status": "open",
            },
            {
                "host": "192.168.1.100",
                "port": "23",
                "service": "Telnet",
                "status": "open",
            },
            {
                "host": "192.168.1.100",
                "port": "443",
                "service": "HTTPS",
                "status": "open",
            },
        ]

        alerts = security_monitor.detect_insecure_services(services)

        self.assertEqual(len(alerts), 2)

        detected_services = " ".join(
            alert["description"] for alert in alerts
        )

        self.assertIn("FTP", detected_services)
        self.assertIn("Telnet", detected_services)


if __name__ == "__main__":
    unittest.main()