import os
import time
import smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage

# --- Configuration ---
FIREWALL_LOG_PATH = r"C:\Users\hp\Documents\pfirewall.log"
EMAIL_ADDRESS = os.getenv("ALERT_EMAIL")
EMAIL_PASSWORD = os.getenv("ALERT_APP_PASSWORD")
COMMON_PORTS = {'21', '22', '23', '80', '139', '443', '445', '3389'}
ALERT_COOLDOWN = 60  # seconds cooldown per IP

# Store last alert time per IP
last_alert_time = {}

def get_alert_log_path():
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return os.path.join(os.path.dirname(__file__), f"alert_log_{timestamp}.txt")

def send_email_alert(src_ip, ports, log_snippet):
    msg = EmailMessage()
    msg['Subject'] = '🚨 Nmap Scan Detected on Your System!'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = EMAIL_ADDRESS

    msg.set_content(f"""
Nmap scan activity detected on your Windows system.

Details:
🔸 Source IP: {src_ip}
🔸 Target Ports: {', '.join(ports)}
🔸 Detected Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Recent Packet Logs:
{log_snippet}
""")

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp.send_message(msg)

def monitor_firewall_log():
    print("[*] Nmap scan detector started. Listening for new scans only...")

    try:
        with open(FIREWALL_LOG_PATH, 'r') as log_file:
            log_file.seek(0, os.SEEK_END)
            last_position = log_file.tell()
    except FileNotFoundError:
        print("[!] Firewall log not found. Exiting.")
        return

    while True:
        try:
            with open(FIREWALL_LOG_PATH, 'r') as log_file:
                log_file.seek(last_position)
                lines = log_file.readlines()
                last_position = log_file.tell()
        except FileNotFoundError:
            time.sleep(3)
            continue

        ip_port_map = {}
        new_logs = []

        now = datetime.now()

        for line in lines:
            if not line.strip():
                continue
            if "ALLOW" in line and "TCP" in line:
                parts = line.split()
                try:
                    proto_index = parts.index("TCP")
                    src_ip = parts[proto_index + 1]
                    dst_port = parts[proto_index + 4]

                    if dst_port in COMMON_PORTS:
                        # Check cooldown
                        last_alert = last_alert_time.get(src_ip)
                        if last_alert and (now - last_alert).total_seconds() < ALERT_COOLDOWN:
                            # Skip this IP due to cooldown
                            continue

                        if src_ip not in ip_port_map:
                            ip_port_map[src_ip] = set()
                        ip_port_map[src_ip].add(dst_port)
                        new_logs.append(line)
                except (ValueError, IndexError):
                    continue

        # Send alerts only for IPs with 2+ ports scanned and outside cooldown
        for ip, ports in ip_port_map.items():
            if len(ports) >= 2:
                print(f"[+] Scan detected from {ip} to ports: {', '.join(ports)}")
                alert_log_path = get_alert_log_path()
                with open(alert_log_path, 'w') as f:
                    f.write(f"[ALERT] Nmap Scan Detected from {ip} to ports: {', '.join(ports)}\n\n")
                    f.writelines(new_logs[-20:])
                send_email_alert(ip, ports, "".join(new_logs[-10:]))

                last_alert_time[ip] = datetime.now()
                print(f"[+] Email sent and alert saved to: {alert_log_path}")
                print("[*] Listening again for new scans...\n")
                break  # One alert per batch

        time.sleep(3)

if __name__ == "__main__":
    monitor_firewall_log()
