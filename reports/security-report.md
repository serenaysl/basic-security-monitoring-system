# Security Monitoring Report

## Overview

For this project, I created a small security monitoring system using simulated network data.

The goal was to detect some common suspicious activities and basic security weaknesses in a simple lab environment.

## Detected Events

The monitoring script detected 5 alerts in total.

### 1. Brute Force Attempt

Source IP:

203.0.113.50

The system detected 8 failed login attempts within 5 minutes.

I marked this as a High severity alert because repeated failed login attempts can indicate a brute-force attack.

### 2. Port Scan

Source IP:

198.51.100.23

The source IP attempted to connect to 10 different ports within 1 minute.

This behavior can indicate that someone is checking which services are available on the target system.

### 3. Suspicious Traffic

Source IP:

192.168.1.25

The system detected a network event containing 5,000,000 bytes of traffic.

I used 1,000,000 bytes as the threshold for this simple lab.

### 4. Open FTP Service

Host:

192.168.1.100

FTP was detected as open on port 21.

FTP can be a security concern because it may transmit credentials and data without encryption.

### 5. Open Telnet Service

Host:

192.168.1.100

Telnet was detected as open on port 23.

Telnet is insecure because its traffic is not encrypted.

## Suggested Actions

Based on the detected alerts, I would suggest:

- Investigating the source of repeated failed login attempts
- Blocking or monitoring suspicious scanning activity
- Checking unusual high-volume network traffic
- Replacing FTP with a secure alternative such as SFTP
- Disabling Telnet and using SSH instead
- Reviewing exposed services regularly

## Result

The monitoring script successfully detected the simulated suspicious activity and saved the results to:

output/alerts.csv

## What I Learned

This project helped me understand how simple rules can be used to detect suspicious behavior in network logs.

I also learned that security monitoring is not only about attacks. Open or insecure services can also create security risks that should be reviewed.
