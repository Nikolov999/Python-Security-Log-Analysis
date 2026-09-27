from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

DATA_FILE = Path(__file__).resolve().parents[1] / "data" / "security_logs.json"
OUTPUT_DIR = Path(__file__).resolve().parents[1] / "outputs"
OUTPUT_DIR.mkdir(exist_ok=True)


def load_data():
    return pd.read_json(DATA_FILE)


def analyse_data(df):
    failed = df[df["status"] == "failed"].copy()
    suspicious = failed[failed["attempts"] >= 5].copy()

    attempts = df["attempts"].to_numpy()

    summary = {
        "total_records": int(len(df)),
        "successful_records": int((df["status"] == "success").sum()),
        "failed_records": int((df["status"] == "failed").sum()),
        "total_attempts": int(np.sum(attempts)),
        "average_attempts": round(float(np.mean(attempts)), 2),
        "maximum_attempts": int(np.max(attempts)),
        "median_attempts": float(np.median(attempts)),
    }

    attempts_by_user = (
        df.groupby("user")["attempts"]
        .sum()
        .sort_values(ascending=False)
    )

    attempts_by_ip = (
        df.groupby("ip")["attempts"]
        .sum()
        .sort_values(ascending=False)
    )

    return summary, suspicious, attempts_by_user, attempts_by_ip


def save_outputs(summary, suspicious, attempts_by_user):
    pd.DataFrame([summary]).to_json(
        OUTPUT_DIR / "library_summary.json",
        orient="records",
        indent=2
    )

    suspicious.to_csv(
        OUTPUT_DIR / "suspicious_logins.csv",
        index=False
    )

    plt.figure(figsize=(8, 5))
    attempts_by_user.plot(kind="bar")
    plt.title("Login Attempts by User")
    plt.xlabel("User")
    plt.ylabel("Total Attempts")
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "attempts_by_user.png")
    plt.close()


def print_report(summary, suspicious, attempts_by_user, attempts_by_ip):
    print("SECURITY LOG ANALYSIS - PANDAS / NUMPY / MATPLOTLIB")
    print("=" * 55)

    for key, value in summary.items():
        print(f"{key:<22}: {value}")

    print()
    print("Attempts by user")
    print(attempts_by_user)

    print()
    print("Attempts by IP")
    print(attempts_by_ip)

    print()
    print("Suspicious failed-login records")
    if suspicious.empty:
        print("None")
    else:
        print(suspicious.to_string(index=False))


def main():
    df = load_data()
    summary, suspicious, attempts_by_user, attempts_by_ip = analyse_data(df)
    print_report(summary, suspicious, attempts_by_user, attempts_by_ip)
    save_outputs(summary, suspicious, attempts_by_user)


if __name__ == "__main__":
    main()
