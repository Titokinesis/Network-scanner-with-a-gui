import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog
import customtkinter as ctk
import nmap
import pandas as pd

# Set the modern dark aesthetic
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

class ScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Automated Reconnaissance Engine")
        self.geometry("900x600")
        
        self.scan_data = []
        self.create_widgets()

    def create_widgets(self):
        # Header text
        self.header_label = ctk.CTkLabel(
            self, 
            text="NETWORK VULNERABILITY SCANNER", 
            font=ctk.CTkFont(size=22, weight="bold")
        )
        self.header_label.pack(pady=(20, 10))

        # Top Control Panel
        control_frame = ctk.CTkFrame(self, corner_radius=10)
        control_frame.pack(pady=10, padx=20, fill="x")

        self.target_entry = ctk.CTkEntry(
            control_frame, 
            placeholder_text="Enter Target IP or Domain (e.g., scanme.nmap.org)", 
            width=350,
            height=40
        )
        self.target_entry.pack(side="left", padx=20, pady=20)
        self.target_entry.insert(0, "scanme.nmap.org")

        self.scan_btn = ctk.CTkButton(
            control_frame, 
            text="INITIATE SCAN", 
            command=self.start_scan, 
            fg_color="#E63946", # Aggressive red color for the scanner
            hover_color="#9B2226",
            height=40,
            font=ctk.CTkFont(weight="bold")
        )
        self.scan_btn.pack(side="left", padx=10)

        self.export_btn = ctk.CTkButton(
            control_frame, 
            text="EXPORT DATA", 
            command=self.export_data, 
            state="disabled",
            height=40,
            font=ctk.CTkFont(weight="bold")
        )
        self.export_btn.pack(side="left", padx=10)

        # Style the standard Treeview table to match the Dark Mode theme
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", 
                        background="#2b2b2b",
                        foreground="white",
                        rowheight=30,
                        fieldbackground="#2b2b2b",
                        borderwidth=0)
        style.map('Treeview', background=[('selected', '#1f538d')])
        style.configure("Treeview.Heading",
                        background="#1f538d",
                        foreground="white",
                        font=("Arial", 10, "bold"))

        # Data Table Container
        table_frame = ctk.CTkFrame(self, corner_radius=10)
        table_frame.pack(pady=10, padx=20, fill="both", expand=True)

        columns = ("Target IP", "Port", "Protocol", "Status", "Service", "Version")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120, anchor=tk.W)

        self.tree.pack(side="left", fill="both", expand=True, padx=10, pady=10)

        # Status Bar
        self.status_var = ctk.StringVar(value="System Ready. Waiting for target input.")
        self.status_bar = ctk.CTkLabel(
            self, 
            textvariable=self.status_var, 
            text_color="gray"
        )
        self.status_bar.pack(side="bottom", pady=15)

    def start_scan(self):
        target = self.target_entry.get().strip()
        if not target:
            return

        self.scan_btn.configure(state="disabled")
        self.export_btn.configure(state="disabled")
        self.status_var.set(f"Executing active scan on {target}... (Please wait)")
        
        # Clear old data
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.scan_data.clear()

        #Running Nmap in background so the UI doesn't freeze
        threading.Thread(target=self.run_nmap_scan, args=(target,), daemon=True).start()

    def run_nmap_scan(self, target):
        scanner = nmap.PortScanner()
        try:
            scanner.scan(target, arguments='-F -sV')
            for host in scanner.all_hosts():
                for proto in scanner[host].all_protocols():
                    ports = scanner[host][proto].keys()
                    for port in sorted(ports):
                        port_data = scanner[host][proto][port]
                        self.scan_data.append({
                            "Target IP": host,
                            "Port": port,
                            "Protocol": proto.upper(),
                            "Status": port_data.get('state', ''),
                            "Service": port_data.get('name', ''),
                            "Version": port_data.get('product', 'Unknown')
                        })
            self.after(0, self.update_table)
        except Exception as e:
            self.after(0, self.handle_scan_error, str(e))

    def update_table(self):
        for row in self.scan_data:
            self.tree.insert("", tk.END, values=(
                row["Target IP"], row["Port"], row["Protocol"], 
                row["Status"], row["Service"], row["Version"]
            ))
        self.scan_btn.configure(state="normal")
        
        if self.scan_data:
            self.export_btn.configure(state="normal")
            self.status_var.set("Scan complete. Targets logged.")
        else:
            self.status_var.set("Scan complete. No open ports discovered.")

    def handle_scan_error(self, error_msg):
        self.scan_btn.configure(state="normal")
        self.status_var.set("Engine Error: Scan failed to execute.")
        print(f"Error details: {error_msg}")

    def export_data(self):
        if not self.scan_data:
            return
        file_path = filedialog.asksaveasfilename(
            defaultextension=".xlsx", 
            filetypes=[("Excel Files", "*.xlsx")], 
            initialfile="Recon_Dataset.xlsx"
        )
        if file_path:
            df = pd.DataFrame(self.scan_data)
            df.to_excel(file_path, index=False)
            self.status_var.set(f"Dataset securely exported to {file_path}")

if __name__ == "__main__":
    app = ScannerApp()
    app.mainloop()