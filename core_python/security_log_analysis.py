import json
from pathlib import Path

DATA_FILE = Path(__file__).resolve().parents[1] / "data" / "security_logs.json"
OUTPUT_DIR = Path(__file__).resolve().parents[1] / "outputs"
OUTPUT_DIR.mkdir(exist_ok=True)


def load_logs(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def analyse_logs(logs):
    total_records = len(logs)
    successful = 0
    failed = 0
    total_attempts = 0

    attempts_by_user = {}
    attempts_by_ip = {}
    suspicious_records = []

    for log in logs:
        total_attempts += log["attempts"]

        if log["status"] == "success":
            successful += 1
        elif log["status"] == "failed":
            failed += 1

        user = log["user"]
        ip = log["ip"]

        attempts_by_user[user] = attempts_by_user.get(user, 0) + log["attempts"]
        attempts_by_ip[ip] = attempts_by_ip.get(ip, 0) + log["attempts"]

        if log["status"] == "failed" and log["attempts"] >= 5:
            suspicious_records.append(log)

    average_attempts = total_attempts / total_records if total_records else 0

    return {
        "total_records": total_records,
        "successful_records": successful,
        "failed_records": failed,
        "total_attempts": total_attempts,
        "average_attempts": round(average_attempts, 2),
        "attempts_by_user": attempts_by_user,
        "attempts_by_ip": attempts_by_ip,
        "suspicious_records": suspicious_records,
    }


def save_summary(summary):
    output_file = OUTPUT_DIR / "core_python_summary.json"
    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(summary, file, indent=2)

    return output_file


def append_alerts(suspicious_records):
    alert_file = OUTPUT_DIR / "security_alerts.txt"

    with open(alert_file, "a", encoding="utf-8") as file:
        for record in suspicious_records:
            file.write(
                f'ALERT | IP={record["ip"]} | '
                f'USER={record["user"]} | '
                f'ATTEMPTS={record["attempts"]} | '
                f'COUNTRY={record["country"]}\n'
            )

    return alert_file


def print_report(summary):
    print("SECURITY LOG ANALYSIS - CORE PYTHON")
    print("=" * 40)
    print(f'Total records:     {summary["total_records"]}')
    print(f'Successful records:{summary["successful_records"]:>5}')
    print(f'Failed records:    {summary["failed_records"]:>5}')
    print(f'Total attempts:    {summary["total_attempts"]:>5}')
    print(f'Average attempts:  {summary["average_attempts"]:>5}')
    print()

    print("Attempts by user")
    for user, attempts in summary["attempts_by_user"].items():
        print(f"  {user:<10} {attempts}")

    print()
    print("Suspicious failed-login records")
    for record in summary["suspicious_records"]:
        print(
            f'  {record["ip"]:<15} '
            f'{record["user"]:<10} '
            f'{record["attempts"]} attempts'
        )


def main():
    logs = load_logs(DATA_FILE)
    summary = analyse_logs(logs)
    print_report(summary)

    summary_path = save_summary(summary)
    alert_path = append_alerts(summary["suspicious_records"])

    print()
    print(f"Summary written to: {summary_path}")
    print(f"Alerts appended to: {alert_path}")


if __name__ == "__main__":
    main()
