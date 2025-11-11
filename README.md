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
   Console & GUI

   <img width="1120" height="623" alt="Screenshot 2025-11-10 183427" src="https://github.com/user-attachments/assets/d2b7ddd7-8a4e-4962-a7f3-c17c1f6c3c8a" />
<img width="1117" height="622" alt="Screenshot 2025-11-10 183402" src="https://github.com/user-attachments/assets/c3b04ca1-d9fa-41ca-a8dd-7613d26e4f2f" />
<img width="1119" height="619" alt="Screenshot 2025-11-10 183344" src="https://github.com/user-attachments/assets/ea2941c5-4351-4132-b29c-294e636e996d" />
<img width="1120" height="841" alt="Screenshot 2025-11-10 183241" src="https://github.com/user-attachments/assets/78862e0c-cfc3-485f-aa01-aeef7d47d510" />

