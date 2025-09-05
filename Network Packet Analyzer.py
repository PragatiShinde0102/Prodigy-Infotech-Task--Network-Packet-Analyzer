import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from scapy.all import sniff, IP
import threading
import csv


class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Analyzer")
        self.root.geometry("900x600")
        self.running = False
        self.protocol_filter = tk.StringVar(value="ALL")
        self.captured_packets = []  # Store packets for saving

        # Frame for buttons
        frame = ttk.Frame(root, padding=10)
        frame.pack(side=tk.TOP, fill=tk.X)

        self.start_button = ttk.Button(frame, text="Start Capture", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(frame, text="Stop Capture", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        self.clear_button = ttk.Button(frame, text="Clear Output", command=self.clear_output)
        self.clear_button.pack(side=tk.LEFT, padx=5)

        self.save_button = ttk.Button(frame, text="Save Packets", command=self.save_packets, state=tk.DISABLED)
        self.save_button.pack(side=tk.LEFT, padx=5)

        # Protocol filter dropdown
        ttk.Label(frame, text="Protocol Filter:").pack(side=tk.LEFT, padx=5)
        self.protocol_menu = ttk.Combobox(frame, textvariable=self.protocol_filter, state="readonly",
                                          values=["ALL", "TCP", "UDP", "ICMP"])
        self.protocol_menu.pack(side=tk.LEFT, padx=5)

        # Packet display area
        self.output_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("Consolas", 10))
        self.output_area.pack(expand=True, fill="both", padx=10, pady=10)

    def packet_callback(self, packet):
        """Process each captured packet and display in GUI."""
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = packet[IP].proto
                payload = bytes(packet[IP].payload)

                # Map protocol numbers
                if proto == 6:
                    protocol = "TCP"
                elif proto == 17:
                    protocol = "UDP"
                elif proto == 1:
                    protocol = "ICMP"
                else:
                    protocol = str(proto)

                # Apply filter
                if self.protocol_filter.get() != "ALL" and protocol != self.protocol_filter.get():
                    return

                info = f"[+] {protocol} Packet | Source: {src_ip} -> Destination: {dst_ip}\n"
                info += f"    Payload: {payload[:50]}\n\n"

                # Save packet details in memory
                self.captured_packets.append([protocol, src_ip, dst_ip, payload[:50]])

                self.output_area.insert(tk.END, info)
                self.output_area.see(tk.END)
                self.save_button.config(state=tk.NORMAL)
        except Exception as e:
            print(f"Error: {e}")

    def start_sniffing(self):
        if not self.running:
            self.running = True
            self.captured_packets.clear()
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            threading.Thread(target=self.sniff_packets, daemon=True).start()

    def sniff_packets(self):
        sniff(prn=self.packet_callback, stop_filter=lambda x: not self.running)

    def stop_sniffing(self):
        if self.running:
            self.running = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            messagebox.showinfo("Stopped", "Packet capturing stopped.")

    def clear_output(self):
        self.output_area.delete(1.0, tk.END)
        self.captured_packets.clear()
        self.save_button.config(state=tk.DISABLED)

    def save_packets(self):
        """Save captured packets to a TXT or CSV file."""
        filetypes = [("Text File", "*.txt"), ("CSV File", "*.csv")]
        filepath = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=filetypes)

        if filepath:
            try:
                if filepath.endswith(".txt"):
                    with open(filepath, "w") as f:
                        for pkt in self.captured_packets:
                            f.write(f"{pkt[0]} | {pkt[1]} -> {pkt[2]} | Payload: {pkt[3]}\n")
                elif filepath.endswith(".csv"):
                    with open(filepath, "w", newline="") as f:
                        writer = csv.writer(f)
                        writer.writerow(["Protocol", "Source IP", "Destination IP", "Payload"])
                        writer.writerows(self.captured_packets)

                messagebox.showinfo("Saved", f"Packets saved to {filepath}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save packets: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
