import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from detector import analyse_logs, generate_report


class TestSSHDetector(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_file = Path(self.temp_dir.name) / "test_auth.log"

    def tearDown(self):
        self.temp_dir.cleanup()

    def run_detector(self, log_lines, threshold=5):
        self.log_file.write_text(
            "\n".join(log_lines) + "\n",
            encoding="utf-8"
        )

        result = analyse_logs(self.log_file)
        failed_attempts, ip_times, successful_logins = result

        output = io.StringIO()
        with redirect_stdout(output):
            generate_report(
                failed_attempts,
                threshold,
                ip_times,
                successful_logins
            )

        return output.getvalue()

    def failed_login(self, time, ip="203.0.113.25"):
        return (
            f"Oct 22 {time} ubuntu sshd[1201]: "
            f"Failed password for invalid user admin "
            f"from {ip} port 50120 ssh2"
        )

    def successful_login(self, time, ip="203.0.113.25"):
        return (
            f"Oct 22 {time} ubuntu sshd[1202]: "
            f"Accepted password for admin "
            f"from {ip} port 50130 ssh2"
        )

    def test_alert_for_five_attempts_within_ten_minutes(self):
        logs = [
            self.failed_login("09:01:12"),
            self.failed_login("09:01:15"),
            self.failed_login("09:01:18"),
            self.failed_login("09:01:21"),
            self.failed_login("09:01:24"),
        ]

        output = self.run_detector(logs)

        self.assertIn("[ALERT]", output)
        self.assertIn("203.0.113.25", output)

    def test_no_alert_when_attempts_are_spread_out(self):
        logs = [
            self.failed_login("09:01:12"),
            self.failed_login("09:04:15"),
            self.failed_login("09:08:18"),
            self.failed_login("09:12:21"),
            self.failed_login("09:15:24"),
        ]

        output = self.run_detector(logs)

        self.assertNotIn("[ALERT]", output)

    def test_warning_for_successful_login_after_failed_attempts(self):
        logs = [
            self.failed_login("09:01:12"),
            self.failed_login("09:01:15"),
            self.failed_login("09:01:18"),
            self.failed_login("09:01:21"),
            self.failed_login("09:01:24"),
            self.successful_login("09:01:30"),
        ]

        output = self.run_detector(logs)

        self.assertIn("[ALERT]", output)
        self.assertIn("[WARNING]", output)

    def test_no_warning_without_successful_login(self):
        logs = [
            self.failed_login("09:01:12"),
            self.failed_login("09:01:15"),
            self.failed_login("09:01:18"),
            self.failed_login("09:01:21"),
            self.failed_login("09:01:24"),
        ]

        output = self.run_detector(logs)

        self.assertIn("[ALERT]", output)
        self.assertNotIn("[WARNING]", output)

    def test_missing_log_file(self):
        output = io.StringIO()

        with redirect_stdout(output):
            result = analyse_logs(self.log_file)

        self.assertIsNone(result)
        self.assertIn("Log file not found", output.getvalue())


if __name__ == "__main__":
    unittest.main()
