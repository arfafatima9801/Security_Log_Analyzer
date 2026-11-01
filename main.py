
import argparse
import sys
import time
from pathlib import Path

from src.parser import parse_file
from src.normalizer import normalize_all
from src.rules import run_all_rules
from src.alerts import create_alerts
from src.storage import save_alerts
from src.config import CONFIG


def parse_arguments():
    """Read input and output paths from the command line."""
    parser = argparse.ArgumentParser(
        description="Security Log Analyzer"
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Path to the input CSV log file"
    )

    parser.add_argument(
        "--output",
        default="output/alerts.csv",
        help="Path where alerts will be saved"
    )

    return parser.parse_args()


def main():
    """Run the complete log analysis pipeline."""
    args = parse_arguments()

    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.is_file():
        print(f"Error: Input file not found: {input_path}")
        return 1

    output_path.parent.mkdir(parents=True, exist_ok=True)

    start_time = time.perf_counter()

    print("=== Security Log Analyzer ===")
    print(f"Input file: {input_path}")
    print(f"Output file: {output_path}")

    try:
        # Step 1: Read and validate raw records
        print("\n[1/5] Parsing records...")
        valid_records, bad_records = parse_file(input_path)

        print(f"Valid records: {len(valid_records)}")
        print(f"Bad records: {len(bad_records)}")

        # Step 2: Convert records into a standard format
        print("\n[2/5] Normalizing events...")
        events = normalize_all(valid_records)
        print(f"Events created: {len(events)}")

        # Step 3: Run the detection rules
        print("\n[3/5] Running detection rules...")
        matches = run_all_rules(events, CONFIG)
        print(f"Total rule matches: {len(matches)}")

        # Step 4: Convert findings into complete alerts
        print("\n[4/5] Creating alerts...")
        alerts = create_alerts(matches)
        print(f"Alerts generated: {len(alerts)}")

        # Step 5: Save alerts to the output file
        print("\n[5/5] Saving alerts...")
        save_alerts(alerts, output_path)

        elapsed = time.perf_counter() - start_time

        # Display final summary
        print("\n=== SUMMARY ===")
        print(f"Events processed: {len(events)}")
        print(f"Bad records: {len(bad_records)}")
        print(f"Alerts generated: {len(alerts)}")

        severity_counts = {}
        rule_counts = {}

        for alert in alerts:
            severity = alert.get("severity", "UNKNOWN")
            rule_id = alert.get("rule_id", "UNKNOWN")

            severity_counts[severity] = (
                severity_counts.get(severity, 0) + 1
            )
            rule_counts[rule_id] = (
                rule_counts.get(rule_id, 0) + 1
            )

        print("\nAlerts by severity:")
        for severity, count in sorted(severity_counts.items()):
            print(f"  {severity}: {count}")

        print("\nAlerts by rule:")
        for rule_id, count in sorted(rule_counts.items()):
            print(f"  {rule_id}: {count}")

        print(f"\nOutput saved to: {output_path}")
        print(f"Processing time: {elapsed:.4f} seconds")
        print("Analysis completed.")

        return 0

    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Error while processing logs: {error}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
