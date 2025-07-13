# Nmap Scan Detector

A Python-based tool that monitors Windows Defender Firewall logs to detect potential Nmap scans on a Windows machine and sends Gmail alerts when suspicious TCP activity is identified. Alerts are also saved to timestamped log files in the script's directory.

## Overview

The Nmap Scan Detector analyzes Windows Defender Firewall logs to identify patterns indicative of Nmap scans, such as rapid connection attempts to multiple common ports (e.g., 21, 22, 80, 443). When suspicious activity is detected, the tool sends an email alert via a Gmail account and saves the alert details to a uniquely timestamped log file. This tool is designed for security enthusiasts, system administrators, or anyone looking to monitor their Windows system for potential reconnaissance activity.

## Features
- Monitors Windows Defender Firewall logs for suspicious TCP activity.
- Detects Nmap scan patterns targeting common ports (e.g., 21, 22, 23, 80, 139, 443, 445, 3389).
- Sends real-time email alerts using Gmail's SMTP server.
- Saves alerts to timestamped log files in the script's directory.
- Implements a 60-second cooldown per IP to prevent alert spam.
- Lightweight and easy to set up.

## Prerequisites
- Windows 10 or later with Windows Defender Firewall enabled.
- Python 3.8 or higher.
- A Gmail account with an App Password for SMTP access (due to Google's security settings).
- Administrator privileges to access firewall logs.

## Installation

1. Clone the Repository:

<pre> git clone https://github.com/yourusername/nmap-scan-detector.git
 cd nmap-scan-detector </pre>

2. **Install Python**: Ensure Python 3.8+ is installed. The script uses standard library modules (`os, time, smtplib, datetime, email.message`), so no additional packages are required.

3. Enable Windows Defender Firewall Logging:
- Open Windows Defender Firewall with Advanced Security.
- Right-click on "Windows Defender Firewall with Advanced Security" and select Properties.
- In the Domain Profile (or relevant profile), click Customize under Logging.
- Enable logging for dropped packets and successful connections.
- Set the log file path to `C:\Users\<YourName>\Documents\pfirewall.log` (replace `<YourName>` with your Windows username).

4. Set Up Gmail App Password:
- Go to your Google Account settings: https://myaccount.google.com/security.
- Enable **2-Step Verification** if not already enabled.
- Create an **App Password** for mail under **Security > App Passwords**.
- Save the generated App Password for use in environment variables.

5. Set Environment Variables: Configure the email settings by setting environment variables (one-time setup). Run the following commands in Command Prompt, replacing the placeholders with your Gmail address and App Password:

<pre> setx ALERT_EMAIL "your_email@gmail.com"
 setx ALERT_APP_PASSWORD "your_gmail_app_password" </pre>

__Note__: Close and reopen your Command Prompt or terminal after setting these variables to ensure they take effect.

## Configuration

1. Verify Firewall Log Path:
- The script uses `C:\Users\<YourName>\Documents\pfirewall.log` as the default log path. Update `FIREWALL_LOG_PATH` in `nmap_scan_detector.py` if your log file is located elsewhere.
- Ensure the script has read access to the log file.

2. Detection Parameters:
- The script monitors common ports (21, 22, 23, 80, 139, 443, 445, 3389).
- It triggers an alert when 2 or more ports are targeted by the same IP within a 60-second window.
- A 60-second cooldown per IP prevents repeated alerts for the same source.

3. Log Files:

Alerts are saved to timestamped files (e.g., `alert_log_2025-07-13_15-43-21.txt`) in the same directory as the script.

## Usage

1. Run the Script:

<pre> python nmap_scan_detector.py </pre>

2. What Happens:

- The script monitors the firewall log file (`C:\Users\<YourName>\Documents\pfirewall.log`) for new TCP connection attempts.
- It detects scans targeting multiple common ports from the same IP.
- When a scan is detected, it:
  - Sends an email alert with the source IP, targeted ports, and recent log snippets.
  - Saves the alert details to a timestamped log file in the script's directory.

3. Example Email Output: When a scan is detected, you receive an email like:

<pre> Subject: 🚨 Nmap Scan Detected on Your System!

Nmap scan activity detected on your Windows system.

Details:
🔸 Source IP: 192.168.1.100
🔸 Target Ports: 22, 80, 443
🔸 Detected Time: 2025-07-13 15:43:21

Recent Packet Logs:
2025-07-13 15:43:20 ALLOW TCP 192.168.1.100 192.168.1.10 12345 22 ...
2025-07-13 15:43:20 ALLOW TCP 192.168.1.100 192.168.1.10 12346 80 ...
</pre>

4. Example Log File Output: A file like `alert_log_2025-07-13_15-43-21.txt` is created with:

<pre>
[ALERT] Nmap Scan Detected from 192.168.1.100 to ports: 22, 80, 443

2025-07-13 15:43:20 ALLOW TCP 192.168.1.100 192.168.1.10 12345 22 ...
2025-07-13 15:43:20 ALLOW TCP 192.168.1.100 192.168.1.10 12346 80 ...
</pre>

5. Stop the Script: Press `Ctrl+C` to stop the monitoring process.

## Customization

- Adjust Detection Parameters: Modify `COMMON_PORTS, ALERT_COOLDOWN,` or the port threshold (currently 2) in `nmap_scan_detector.py` to tune scan detection sensitivity.
- Change Log Path: Update `FIREWALL_LOG_PATH` in the script to match your firewall log location.
- Alternative Notifications: Modify the `send_email_alert` function to support other notification methods (e.g., Slack, SMS).

## Troubleshooting
- No Email Alerts:
  - Verify `ALERT_EMAIL` and `ALERT_APP_PASSWORD` environment variables are set correctly (`echo %ALERT_EMAIL%` in Command Prompt).
  - Ensure your internet connection is active and Gmail's SMTP settings are correct.
- No Logs Detected:
  - Confirm Windows Defender Firewall logging is enabled and the log path is set to `C:\Users\<YourName>\Documents\pfirewall.log`.
  - Verify the script has permission to read the log file.
- False Positives:
  - Adjust the port threshold or `ALERT_COOLDOWN` in the script to reduce sensitivity.
- Log File Not Found:
  - Ensure the firewall log path exists and is accessible. Update `FIREWALL_LOG_PATH` if needed.

## Contributing

Contributions are welcome! Please follow these steps:
1. Fork the repository.
2. Create a new branch (`git checkout -b feature-name`).
3. Commit your changes (`git commit -m "Add feature-name"`).
4. Push to the branch (`git push origin feature-name`).
5. Open a Pull Request.

## License

This project is licensed under the **GNU General Public License v3.0**.

## Disclaimer

This tool is for educational and defensive purposes only. Ensure you have permission to monitor systems and networks. Misuse of this tool may violate applicable laws or policies.
