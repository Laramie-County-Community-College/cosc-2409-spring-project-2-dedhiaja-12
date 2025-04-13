import re
import random
import datetime

def generate_log_entry(ip_address, url, status_code):
    """
    Generates a single log entry line in the following format:
    YYYY-MM-DD HH:MM:SS - IP_ADDRESS - "GET /some/url HTTP/1.1" STATUS_CODE
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"{timestamp} - {ip_address} - \"GET {url} HTTP/1.1\" {status_code}\n"

def generate_log_file(filename="access.log", num_entries=100):
    """
    Generates a sample log file with the specified number of entries.

    Parameters:
    - filename: Name of the log file to write to.
    - num_entries: Number of log entries to generate.
    """
    ip_addresses = [f"192.168.1.{i}" for i in range(1, 25)]
    urls = ["/page1", "/page2", "/page3", "/images/logo.png", "/api/data"]
    status_codes = [200, 404, 500, 301]

    with open(filename, "w") as f:
        for _ in range(num_entries):
            ip = random.choice(ip_addresses)
            url = random.choice(urls)
            status = random.choice(status_codes)
            f.write(generate_log_entry(ip, url, status))

if __name__ == "__main__":
    generate_log_file()
