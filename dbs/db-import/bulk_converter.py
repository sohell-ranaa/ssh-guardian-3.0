#!/usr/bin/env python3
"""
SQL Dump Bulk Converter
Converts individual INSERT statements into bulk INSERT statements.
Combines up to BATCH_SIZE values per INSERT for faster imports.
"""

import re
import sys
import time
from pathlib import Path

# Configuration
BATCH_SIZE = 10000
INPUT_FILE = Path(__file__).parent / "back_ssh_guardian_v3.sql"
OUTPUT_FILE = Path(__file__).parent / "bulk_ssh_guardian_v3.sql"

# Regex to match INSERT statements
INSERT_PATTERN = re.compile(r"INSERT INTO\s+(`?\w+`?)\s+VALUES\s*\((.+)\);", re.IGNORECASE)


def log(message):
    """Print timestamped log message."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")


def convert_to_bulk(input_path, output_path, batch_size=1000):
    """
    Convert individual INSERT statements to bulk INSERT statements.

    Args:
        input_path: Path to input SQL file
        output_path: Path to output SQL file
        batch_size: Maximum number of VALUES per INSERT statement
    """
    log(f"Input file: {input_path}")
    log(f"Output file: {output_path}")
    log(f"Batch size: {batch_size}")

    input_size = input_path.stat().st_size / (1024 * 1024)
    log(f"Input file size: {input_size:.1f} MB")

    start_time = time.time()

    current_table = None
    values_buffer = []
    line_count = 0
    insert_count_in = 0
    insert_count_out = 0

    with open(input_path, 'r', encoding='utf-8', errors='replace') as infile, \
         open(output_path, 'w', encoding='utf-8') as outfile:

        def flush_buffer():
            """Write buffered VALUES as a bulk INSERT."""
            nonlocal values_buffer, current_table, insert_count_out
            if values_buffer and current_table:
                outfile.write(f"INSERT INTO {current_table} VALUES\n")
                outfile.write(",\n".join(f"({v})" for v in values_buffer))
                outfile.write(";\n")
                insert_count_out += 1
                values_buffer = []

        for line in infile:
            line_count += 1

            # Progress update every 500k lines
            if line_count % 500000 == 0:
                elapsed = time.time() - start_time
                log(f"  Progress: {line_count:,} lines ({elapsed:.1f}s)")

            # Try to match INSERT statement
            match = INSERT_PATTERN.match(line.strip())

            if match:
                table = match.group(1)
                values = match.group(2)
                insert_count_in += 1

                # If table changed or buffer full, flush
                if table != current_table:
                    flush_buffer()
                    current_table = table

                if len(values_buffer) >= batch_size:
                    flush_buffer()
                    current_table = table

                values_buffer.append(values)
            else:
                # Non-INSERT line, flush buffer and write line as-is
                flush_buffer()
                current_table = None
                outfile.write(line)

        # Flush any remaining buffer
        flush_buffer()

    elapsed = time.time() - start_time
    output_size = output_path.stat().st_size / (1024 * 1024)

    log("=" * 60)
    log("Conversion complete!")
    log(f"  Time elapsed: {elapsed:.1f}s")
    log(f"  Lines processed: {line_count:,}")
    log(f"  INSERT statements in original: {insert_count_in:,}")
    log(f"  INSERT statements in output: {insert_count_out:,}")
    log(f"  Reduction ratio: {insert_count_in / max(insert_count_out, 1):.1f}x")
    log(f"  Input size: {input_size:.1f} MB")
    log(f"  Output size: {output_size:.1f} MB")
    log("=" * 60)

    return insert_count_in, insert_count_out


def main():
    log("=" * 60)
    log("SQL Dump Bulk Converter")
    log("=" * 60)

    if not INPUT_FILE.exists():
        log(f"Error: Input file not found: {INPUT_FILE}")
        sys.exit(1)

    convert_to_bulk(INPUT_FILE, OUTPUT_FILE, BATCH_SIZE)


if __name__ == "__main__":
    main()
