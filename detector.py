from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
import argparse

LOG_FILE = Path("sample_auth.log")
THRESHOLD = 5


def analyse_logs(log_file):
    failed_attempts = Counter()
    ip_times = {}
    successful_logins = {}

    if not log_file.exists():
        print(f"[ERROR] Log file not found: {log_file}")
        return None

    with log_file.open("r", encoding="utf-8") as file:
        for line in file:
            if "Failed password" in line:
                timestamp_text = line[:15]
                current_year = datetime.now().year
                timestamp_with_year = str(current_year) + " " + timestamp_text
                timestamp = datetime.strptime(timestamp_with_year, "%Y %b %d %H:%M:%S")
                parts = line.split()

                if "from" in parts:
                    ip_index = parts.index("from") + 1

                    if ip_index < len(parts):
                        ip_address = parts[ip_index]
                        failed_attempts[ip_address] += 1
                        ip_times.setdefault(ip_address, []).append(timestamp)
            if "Accepted password" in line:
                timestamp_text = line[:15]
                current_year = datetime.now().year
                timestamp_with_year = str(current_year) + " " + timestamp_text
                timestamp = datetime.strptime(timestamp_with_year, "%Y %b %d %H:%M:%S")
                parts = line.split()

                if "from" in parts:
                    ip_index = parts.index("from") + 1

                    if ip_index < len(parts):
                        ip_address = parts[ip_index]
                        successful_logins.setdefault(ip_address, []).append(timestamp)

    return failed_attempts, ip_times, successful_logins


def generate_report(failed_attempts, threshold, ip_times, successful_logins):
    print("\nSSH Brute-Force Detection Report")
    print("=" * 35)

    window = timedelta(minutes=10)
    suspicious_ips = []

    for ip_address, count in failed_attempts.items():
        times = sorted(ip_times.get(ip_address, []))
        window_start = 0
        max_attempts = 0
        for window_end in range(len(times)):
            while times[window_end] - times[window_start] > window:
                window_start += 1
            attempts_in_window = window_end - window_start + 1
            max_attempts = max(max_attempts, attempts_in_window)
        if max_attempts >= threshold:
            print(
                f"[ALERT] {ip_address}: "
                f"{max_attempts} failed login attempts within 10 minutes"
            )
            suspicious_ips.append(ip_address)
            successful_times = successful_logins.get(ip_address, [])
            if any(success_time > times[-1] for success_time in successful_times):
                print(f"[WARNING] {ip_address} succesful login after failed attempts")
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

    result = analyse_logs(LOG_FILE)
    if result is not None:
        failed_attempts, ip_times, successful_logins = result
        generate_report(
            failed_attempts, args.threshold, ip_times, successful_logins
        )



if __name__ == "__main__":
    main()
