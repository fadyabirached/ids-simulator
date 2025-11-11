

import random      
import time        



def random_ip():
    return ".".join(str(random.randint(0, 255)) for _ in range(4))  



def generate_normal_traffic(n_events):
   
    events = []  

    common_ports = [80, 443, 22, 21, 53, 110]  

    for _ in range(n_events):                  
        event = {
            "source_ip": random_ip(),         
            "destination_ip": random_ip(),
            "destination_port": random.choice(common_ports),
            "timestamp": time.time()           
        }
        events.append(event)                   

    return events



def inject_port_scan(events, n_ports=30):
   
    attacker = random_ip()
    target = random_ip()

    used_ports = set()  

    while len(used_ports) < n_ports:
        port = random.randint(1, 65535)  

        if port in used_ports:  
            continue

        used_ports.add(port)

        event = {
            "source_ip": attacker,
            "destination_ip": target,
            "destination_port": port,
            "timestamp": time.time()
        }
        events.append(event)

    return attacker  


def inject_dos_attack(events, n_attackers=60):
   
    target = random_ip()
    dst_port = 80

    attacker_ips = set()

    while len(attacker_ips) < n_attackers:
        attacker_ips.add(random_ip())  

    for ip in attacker_ips:  
        event = {
            "source_ip": ip,
            "destination_ip": target,
            "destination_port": dst_port,
            "timestamp": time.time()
        }
        events.append(event)

    return attacker_ips 
