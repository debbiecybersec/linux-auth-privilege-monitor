#!/usr/bin/env python3

import re
from collections import defaultdict
from datetime import datetime

LOG_FILE = "logs/auth.log"
REPORT_FILE = "reports/privilege_report.txt"

# Patterns to detect privilege-related events in auth.log
SUDO_PATTERN = re.compile(r"sudo: (\w+) : .*COMMAND=(.+)")
SU_PATTERN = re.compile(r"su: .*session opened for user (\w+)")

def analyze_auth_log():
    sudo_commands = defaultdict(int)
    su_sessions = defaultdict(int)
    total_lines = 0

    try:
        with open(LOG_FILE, "r") as f:
            for line in f:
                total_lines += 1

                sudo_match = SUDO_PATTERN.search(line)
                if sudo_match:
                    user = sudo_match.group(1)
                    command = sudo_match.group(2)
                    sudo_commands[f"{user} -> {command}"] += 1

                su_match = SU_PATTERN.search(line)
                if su_match:
                    target_user = su_match.group(1)
                    su_sessions[target_user] += 1

    except FileNotFoundError:
        print(f"[!] Log file not found: {LOG_FILE}")
        print("    Create it or change LOG_FILE path.")
        return

    # Write report
    with open(REPORT_FILE, "w") as r:
        r.write("Linux Auth & Privilege Monitor Report\n")
        r.write("=" * 40 + "\n")
        r.write(f"Analyzed log: {LOG_FILE}\n")
        r.write(f"Total lines scanned: {total_lines}\n")
        r.write(f"Generated: {datetime.now()}\n\n")

        r.write("SUDO Commands Observed:\n")
        if sudo_commands:
            for item, count in sorted(sudo_commands.items(), key=lambda x: x[1], reverse=True):
                r.write(f"  - {item}  (x{count})\n")
        else:
            r.write("  None found.\n")

        r.write("\nSU Sessions Observed:\n")
        if su_sessions:
            for user, count in su_sessions.items():
                r.write(f"  - su to {user}  (x{count})\n")
        else:
            r.write("  None found.\n")

    print(f"[+] Analysis complete. Report saved to {REPORT_FILE}")

if __name__ == "__main__":
    analyze_auth_log()


Jan 03 10:01:12 kali sudo: twinzi : TTY=pts/0 ; PWD=/home/twinzi ; USER=root ; COMMAND=/usr/bin/apt update
Jan 03 10:02:10 kali sudo: twinzi : TTY=pts/0 ; PWD=/home/twinzi ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
Jan 03 10:03:05 kali su: pam_unix(su:session): session opened for user root by twinzi(uid=1000)
