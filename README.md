# Basic Security Monitoring System



This project is a simple security monitoring system that I built with Python.



I created it to practice detecting suspicious activity and basic security problems in a simulated network environment.



## What the System Detects



The monitoring system checks for:



\- Brute-force login attempts

\- Port scanning activity

\- Unusually large network traffic

\- Open FTP services

\- Open Telnet services



## How It Works



The project mainly uses two Python scripts.



`generate\_sample\_data.py` creates simulated network activity and service data.



`security\_monitor.py` reads this data and applies simple detection rules.



The current detection rules are:



| Detection | Rule |

| --- | --- |

| Brute Force | More than 5 failed logins within 5 minutes |

| Port Scan | 8 or more different ports within 1 minute |

| Suspicious Traffic | More than 1,000,000 bytes in one event |

| Potential Vulnerability | FTP or Telnet service is open |



The threshold values are stored in:



```text

config.json

```



This makes it possible to change the detection settings without editing the main Python script.



\## Project Structure



```text

basic-security-monitoring-system/

│

├── config.json

├── README.md

├── requirements.txt

│

├── data/

│   ├── network\_events.csv

│   └── services.csv

│

├── output/

│   └── alerts.csv

│

├── reports/

│   └── security-report.md

│

├── src/

│   ├── generate\_sample\_data.py

│   └── security\_monitor.py

│

└── tests/

&#x20;   └── test\_security\_monitor.py

```



## How to Run



First, generate the sample network data:



```bash

python src/generate\_sample\_data.py

```



Then run the monitoring system:



```bash

python src/security\_monitor.py

```



## Test Result



During my test, the system generated 5 alerts:



\- 1 Brute Force alert

\- 1 Port Scan alert

\- 1 Suspicious Traffic alert

\- 2 Potential Vulnerability alerts



The detected alerts are saved in:



```text

output/alerts.csv

```



The detailed security findings are available in:



```text

reports/security-report.md

```



\## Unit Tests



I also added unit tests for the main detection rules.



The tests check brute-force detection, the exact brute-force threshold, port scanning, large traffic events and insecure services.



Run the tests with:



```bash

python -m unittest discover -s tests -v

```



Test result:



```text

Ran 5 tests



OK

```



## Technologies



\- Python

\- CSV

\- JSON

\- Python standard library

\- unittest



## Limitations



This project uses simulated CSV data and simple threshold-based detection rules.



It is a learning project, not a production security monitoring system. Normal activity could sometimes cross one of the thresholds and create a false positive.



The current version also does not include real-time packet capture, threat intelligence, automatic blocking or long-term event correlation.



## What I Learned



This project helped me understand how basic monitoring rules can be used to detect suspicious activity.



I practiced working with failed login attempts, port activity, traffic size and insecure services. I also learned how configuration files and unit tests can make a small security project easier to manage and test.

