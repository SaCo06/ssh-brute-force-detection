from collections import Counter
from pathlib import Path
import argparse

LOG_FILE = Path("sample_auth.log")
THRESHOLD = 5


def analyse_logs(log_file):
    failed_attempts = Counter()

    if not log_file.exists():
        print(f"[ERROR] Log file not found: {log_file}")
        return None

    with log_file.open("r", encoding="utf-8") as file:
        for line in file:
            if "Failed password" in line:
                parts = line.split()

                if "from" in parts:
                    ip_index = parts.index("from") + 1

                    if ip_index < len(parts):
                        ip_address = parts[ip_index]
                        failed_attempts[ip_address] += 1

    return failed_attempts


def generate_report(failed_attempts, threshold):
    print("\nSSH Brute-Force Detection Report")
    print("=" * 35)

    suspicious_ips = []

    for ip_address, count in failed_attempts.items():
        if count >= threshold:
            print(
                f"[ALERT] {ip_address}: "
                f"{count} failed login attempts"
            )
            suspicious_ips.append(ip_address)
        else:
            print(
                f"[INFO] {ip_address}: "
                f"{count} failed login attempts"
            )

    if suspicious_ips:
        print("\nRecommended next steps:")
        print("- Review the authentication logs.")
        print("- Check whether any login succeeded afterward.")
        print("- Investigate the source and affected accounts.")
        print("- Consider containment according to security policy.")
    else:
        print("\nNo IP addresses exceeded the threshold.")



def main():
    parser = argparse.ArgumentParser(
        description="Detect suspicious SSH login activity."
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=THRESHOLD,
        help="Minimum failed attempts required for an alert."
    )
    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("Threshold must be at least 1.")

    failed_attempts = analyse_logs(LOG_FILE)

    if failed_attempts is not None:
        generate_report(failed_attempts, args.threshold)



if __name__ == "__main__":
    main()
