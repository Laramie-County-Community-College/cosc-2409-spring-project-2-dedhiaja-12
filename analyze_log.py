import re
import os

def analyze_log_file(filename="access.log"):
    try:
        with open(filename, "r") as f:
            log_lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: Log file '{filename}' not found.")
        return

    error_count = 0
    unique_ips = set()
    url_counts = {}

    for line in log_lines:
        timestamp, ip, url, status_code = extract_log_data(line)
        if not all([timestamp, ip, url, status_code]):
            continue
        unique_ips.add(ip)
        if url in url_counts:
            url_counts[url] += 1
        else:
            url_counts[url] = 1
        try:
            if int(status_code) >= 400:
                error_count += 1
        except ValueError:
            continue

    print(f"Total Errors (4xx and 5xx): {error_count}")
    print(f"Unique IP Addresses: {len(unique_ips)}")
    print("URL Access Counts:")
    for url, count in sorted(url_counts.items(), key=lambda item: item[1], reverse=True):
        print(f"    {url}: {count}")

def extract_log_data(line):
    match = re.search(
        r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - \"GET (.+) HTTP/1.1\" (\d+)",
        line)
    if match:
        return match.groups()
    else:
        return None, None, None, None
analyze_log_file()
