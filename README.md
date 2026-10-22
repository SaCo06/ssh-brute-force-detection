SSH Brute-Force Detection

A small Python-based cybersecurity project that analyses simulated Linux SSH authentication logs to identify potentially suspicious login activity.

This project was created as a hands-on learning exercise in **Blue Team security monitoring, log analysis and basic incident response**.

## Features

- Analyses Linux-style SSH authentication logs.
- Counts failed login attempts per source IP address.
- Generates an alert when an IP address reaches a configurable threshold.
- Provides basic incident investigation recommendations.
- Handles missing log files and invalid threshold values.

## Technologies

- Python 3
- Python standard library: `collections`, `pathlib` and `argparse`
- Simulated Linux SSH authentication logs

No external Python packages are required.

## Getting Started

### Requirements

Python 3 installed on your system.

### Run the detector

Clone or download this repository and open a terminal in the project directory.

Run the detector with the default threshold of five failed login attempts:

```bash
python detector.py
```

Set a custom threshold:

```bash
python detector.py --threshold 6
```

The threshold must be a positive integer.

## Example Detection Scenario

The included sample log file contains simulated SSH authentication events.

| Source IP | Failed attempts | Expected result |
|---|---:|---|
| `203.0.113.25` | 5 | Alert at threshold 5 |
| `198.51.100.42` | 2 | Informational message |
| `192.0.2.10` | 0 | Successful login; not counted as a failure |

The detector counts failed password events. Successful logins are not counted as failed attempts.

## Testing

The following scenarios were tested manually:

- Default threshold: an alert is generated for an IP with five failed attempts.
- Higher threshold (`--threshold 6`): no alert is generated for the sample IP addresses.
- Invalid threshold (`--threshold 0`): the program rejects the input.
- Missing log file: the program displays an error message.

## Limitations

- The project uses simulated log data, not live system monitoring.
- A high number of failed logins may indicate suspicious activity, but does not prove an attack.
- The detector does not currently correlate events over time or detect successful account compromise.
- IP addresses can be shared, spoofed in some contexts, or associated with legitimate users.
- The tool is a learning proof of concept, not a production-ready security monitoring solution.

## Possible Improvements

- Add timestamp-based detection windows.
- Export alerts to JSON or CSV.
- Add automated unit tests.
- Integrate with a SIEM or centralised logging platform.

## Disclaimer

This project is intended for educational purposes. All included log entries are simulated.

## Acknowledgements & AI Disclosure

This project was developed as a personal learning exercise in cybersecurity, with guidance and assistance from ChatGPT (OpenAI).

AI assistance was used to help structure the project, explain implementation choices, develop the Python code and identify test scenarios. The code was run and the described test scenarios were checked during development.

The project builds on common cybersecurity concepts, including SSH brute-force detection and authentication log analysis. It is an educational proof of concept rather than an original security research project or a production-ready tool.

