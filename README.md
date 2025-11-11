# 🔐 Cyber Intrusion Detection System (IDS) Simulator  
A Python-based simulator for generating network traffic, injecting cyber attacks, detecting anomalies, and visualizing results.

---

## 📌 Overview  
This project simulates network activity and applies basic rule-based intrusion detection techniques to identify malicious behavior such as *Port Scans* and *Denial-of-Service (DoS)* attacks.  
It includes:

✅ Traffic simulation  
✅ Attack injection  
✅ Port scan + DoS detection  
✅ False-positive filtering (whitelist)  
✅ Analytics  
✅ Matplotlib visual charts  
✅ GUI (Tkinter) + CLI (main.py)

---

## 🎯 Project Objectives  

The IDS Simulator is designed to:

1. *Generate synthetic network events*  
   Each event is a dictionary containing:
   - source_ip
   - destination_ip
   - destination_port
   - timestamp

2. *Inject malicious traffic*
   - *Port Scan:* one attacker connects to many ports on one target  
   - *DoS Attack:* many attackers flood the same IP/port in a short time  

3. *Detect attacks (Rule-Based)*  
   - *Port Scan Detector:* flags an IP scanning >20 ports  
   - *DoS Detector:* flags >50 unique IPs hitting the same destination  

4. *Filter false positives*  
   - Whitelist trusted IPs  
   - Only analyze non-whitelisted sources  

5. *Visualize analytics*  
   Charts include:
   - Top Source IPs  
   - Top Destination IPs  
   - Top Ports  
   Malicious IPs are highlighted in *red*.

6. *Display alerts*  
   Console & GUI messages like:
