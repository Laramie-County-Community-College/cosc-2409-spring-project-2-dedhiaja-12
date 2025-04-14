import re
import os
def analyze_log_file(filename="access.log"):
    """Analyzes a log file and extracts information.

    This function opens the log file, reads each line, and performs analysis based on the extracted data.
    """
    try:
        with open(filename, "r") as f:
            log_lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: Log file '{filename}' not found.")
        return
    unique_ips = set()
    url_counts = {}
    error_count = 0
    for line in log_lines:
        timestamp, ip, url, status_code = extract_log_data(line)
        if timestamp and ip and url and status_code:
            # Track unique IP addresses
            unique_ips.add(ip)
            # Count URL access
            if url in url_counts:
                url_counts[url] += 1
            else:
                url_counts[url] = 1
            # Count errors (status codes 4xx and 5xx)
            if int(status_code) >= 400:
                error_count += 1
    # Print the summary
    print(f"Total Errors (4xx and 5xx): {error_count}")
    print(f"Unique IP Addresses: {len(unique_ips)}")
    print("URL Access Counts:")
    for url, count in sorted(url_counts.items()):
        print(f"    {url}: {count}")
def extract_log_data(line):
    """Extracts timestamp, IP address, URL, and status code from a valid log line."""
    match = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - \"GET (.+) HTTP/1.1\" (\d+)", line)
    if match:
        timestamp, ip, url, status_code = match.groups()
        return timestamp, ip, url, status_code
    else:
        return None, None, None, None
# Analyze the log file
if __name__ == "__main__":
    analyze_log_file()
