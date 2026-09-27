\# Basic Security Monitoring System



This project is a small security monitoring system built with Python.



I created it to practice detecting suspicious activity and basic vulnerabilities in a simulated network environment.



\## What the System Detects



The monitoring script checks for:



\- Brute-force login attempts

\- Port scanning activity

\- Unusually large network traffic

\- Open FTP service

\- Open Telnet service



\## How It Works



The project has two Python scripts.



generate\_sample\_data.py creates simulated network activity.



security\_monitor.py reads the data and checks for suspicious behavior.



The detection rules are:



\- More than 5 failed logins within 5 minutes = Brute Force

\- 8 or more different ports within 1 minute = Port Scan

\- More than 1,000,000 bytes in one event = Suspicious Traffic

\- Open FTP or Telnet = Potential Vulnerability



\## How to Run



Generate the sample data:



python src/generate\_sample\_data.py



Run the monitoring system:



python src/security\_monitor.py



\## Test Result



During my test, the system generated 5 alerts:



\- 1 Brute Force alert

\- 1 Port Scan alert

\- 1 Suspicious Traffic alert

\- 2 Potential Vulnerability alerts



The alerts are stored in:



output/alerts.csv



The detailed report is available in:



reports/security-report.md



\## Technologies



\- Python

\- CSV

\- Python standard library



\## What I Learned



This project helped me understand how basic monitoring rules can detect suspicious activity in network data.



I practiced checking failed logins, port activity, traffic size and insecure services.



I also learned that simple thresholds can work in a lab, but a real monitoring system would need more advanced rules to reduce false positives.



\## Tests



I added unit tests for the main detection rules.



The tests check:



\- Brute-force detection

\- The exact brute-force threshold

\- Port scan detection

\- Large traffic detection

\- Insecure service detection



Run the tests with:



python -m unittest discover -s tests -v



Test result:



5 tests passed successfully.



\## Limitations



This project uses simulated CSV data and simple threshold-based rules.



Because of that, it is designed as a learning project rather than a production monitoring system.



Possible limitations include:



\- False positives when normal activity crosses a threshold

\- No real-time packet capture

\- No external threat intelligence

\- No automatic blocking or response action

\- No long-term event correlation



In a real environment, these rules would need more context and tuning.

