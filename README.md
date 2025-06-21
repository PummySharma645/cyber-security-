# cyber-security-
import re
from collections import defaultdict
from datetime import datetime, timedelta

# Sample path to your system log file (use real path in actual use)
log_file = 'auth.log'

# Store failed login attempts by IP address
failed_attempts = defaultdict(list)

# Define time window and threshold
time_window = timedelta(minutes=2)
attempt_threshold = 5

# Regular expression to match failed login attempts
# Example log line:
# Jun 21 10:05:32 myhost sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2
pattern = re.compile(r'^(\w+\s+\d+\s+\d+:\d+:\d+).*Failed password.*from ([\d\.]+)')

with open(log_file, 'r') as f:
    for line in f:
        match = pattern.match(line)
        if match:
            # Parse timestamp and IP
            timestamp_str, ip = match.groups()
            timestamp = datetime.strptime(timestamp_str, '%b %d %H:%M:%S')

            # Save attempt
            failed_attempts[ip].append(timestamp)

# Analyze attempts
print("🚨 Suspicious IPs (possible brute-force):")
for ip, times in failed_attempts.items():
    times.sort()
    for i in range(len(times)):
        window = times[i:i + attempt_threshold]
        if len(window) == attempt_threshold and (window[-1] - window[0]) <= time_window:
            print(f"⚠️  IP {ip} had {attempt_threshold} failed attempts in {time_window}.")
            break
