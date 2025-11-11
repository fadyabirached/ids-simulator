

import tkinter as tk
from tkinter import scrolledtext, messagebox
from pathlib import Path
from simulator import generate_normal_traffic, inject_port_scan, inject_dos_attack
from filters import filter_by_whitelist
from detectors import run_all_detectors
from analytics import count_sources, count_destinations, count_ports
from visualizer import plot_top_counts
from storage import save_log_csv


class IDSSimulatorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AI-Based IDS Simulator")
        self.root.geometry("900x650")
        self.root.configure(bg="#1e1e1e")  

        header = tk.Frame(self.root, bg="#282828", height=70)
        header.pack(fill="x")

        title_label = tk.Label(
            header,
            text="💻 Intrusion Detection System Simulator",
            bg="#282828",
            fg="#00c8ff",
            font=("Segoe UI", 20, "bold"),
            pady=15,
        )
        title_label.pack()

        button_frame = tk.Frame(self.root, bg="#1e1e1e")
        button_frame.pack(pady=15)

        self.btn_generate = tk.Button(
            button_frame,
            text="🟢 Generate Data",
            bg="#00ff88",
            fg="black",
            font=("Segoe UI", 11, "bold"),
            width=18,
            relief="raised",
            command=self.generate_data,
        )
        self.btn_generate.grid(row=0, column=0, padx=8)

        self.btn_detect = tk.Button(
            button_frame,
            text="🟠 Run Detection",
            bg="#ffaa00",
            fg="black",
            font=("Segoe UI", 11, "bold"),
            width=18,
            relief="raised",
            command=self.run_detection,
        )
        self.btn_detect.grid(row=0, column=1, padx=8)

        self.btn_visual = tk.Button(
            button_frame,
            text="🔵 Show Charts",
            bg="#0099ff",
            fg="white",
            font=("Segoe UI", 11, "bold"),
            width=18,
            relief="raised",
            command=self.show_charts,
        )
        self.btn_visual.grid(row=0, column=2, padx=8)

        log_frame = tk.LabelFrame(
            self.root, text="📜 System Log", bg="#1e1e1e", fg="#00c8ff", font=("Segoe UI", 12, "bold")
        )
        log_frame.pack(fill="both", expand=True, padx=20, pady=10)

        self.text_area = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.WORD,
            width=100,
            height=30,
            font=("Consolas", 10),
            bg="#111",
            fg="#00ff99",
            insertbackground="white",  
        )
        self.text_area.pack(padx=10, pady=10, fill="both", expand=True)

        footer = tk.Label(
            self.root,
            text="Developed by Fady Abi Rached | Programming for AI Project",
            bg="#282828",
            fg="#cccccc",
            font=("Segoe UI", 10),
        )
        footer.pack(side="bottom", fill="x")

        self.events = []
        self.alerts = []
        self.malicious_ips = set()
        self.analytics = {}

    def log(self, text):
        self.text_area.insert(tk.END, text + "\n")
        self.text_area.see(tk.END)
        self.root.update()

    def generate_data(self):
        self.text_area.delete(1.0, tk.END)
        self.log("🟢 Generating traffic...")

        Path("data").mkdir(parents=True, exist_ok=True)

        self.events = generate_normal_traffic(200)
        inject_port_scan(self.events, n_ports=30)
        inject_dos_attack(self.events, n_attackers=60)

        whitelist = {"127.0.0.1", "10.0.0.1"}
        self.events = filter_by_whitelist(self.events, whitelist)
        save_log_csv("data/traffic.csv", self.events)

        self.log(f"✅ Data generated: {len(self.events)} events saved to data/traffic.csv")

    def run_detection(self):
        if not self.events:
            messagebox.showwarning("⚠️ Warning", "Please generate data first!")
            return

        self.log("\n🟠 Running detectors...")
        self.alerts, self.malicious_ips = run_all_detectors(
            self.events, port_threshold=20, dos_src_threshold=50
        )

        if not self.alerts:
            self.log("✅ No alerts detected.")
        else:
            for alert in self.alerts:
                self.log(alert)
            self.log(f"🚨 Total alerts: {len(self.alerts)}")

        if self.malicious_ips:
            self.log("\n🚫 Malicious source IPs:")
            for ip in list(self.malicious_ips)[:10]:
                self.log(f" - {ip}")

        src_counts = count_sources(self.events)
        dst_counts = count_destinations(self.events)
        port_counts = count_ports(self.events)
        self.analytics = {"src": src_counts, "dst": dst_counts, "port": port_counts}
        self.log("\n📊 Analytics computed successfully.")

    def show_charts(self):
        if not self.analytics:
            messagebox.showwarning("⚠️ Warning", "Run detection first!")
            return

        self.log("\n🔵 Generating charts...")
        plot_top_counts(self.analytics["src"], "Top Source IPs", top_n=10, malicious_ips=self.malicious_ips)
        plot_top_counts(self.analytics["dst"], "Top Destination IPs", top_n=10, malicious_ips=self.malicious_ips)
        plot_top_counts(self.analytics["port"], "Top Destination Ports", top_n=10)


if __name__ == "__main__":
    root = tk.Tk()
    app = IDSSimulatorGUI(root)
    root.mainloop()
