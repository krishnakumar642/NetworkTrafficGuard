import queue
import sqlite3
import threading
import tkinter as tk
from collections import Counter
from tkinter import ttk

from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
from scapy.all import IP, sniff

# Database Setup
conn = sqlite3.connect("network_packets.db", check_same_thread=False)
cursor = conn.cursor()
cursor.execute(
    """
    CREATE TABLE IF NOT EXISTS packets
    (id INTEGER PRIMARY KEY AUTOINCREMENT,
     source TEXT,
     destination TEXT,
     protocol TEXT)
"""
)
conn.commit()

# Queue & Data Structures
packet_queue = queue.Queue(maxsize=1000)
PROTOS = {1: "ICMP", 6: "TCP", 17: "UDP"}
proto_count = Counter()
stop_sniffing_event = threading.Event()

# Blocked IPs List
BLOCKED_IPS = {"192.168.1.50", "10.0.0.99"}


def packet_callback(packet):
    if packet.haslayer(IP) and not stop_sniffing_event.is_set():
        src = packet[IP].src
        dst = packet[IP].dst

        # IP Blocking Mechanism
        if src in BLOCKED_IPS or dst in BLOCKED_IPS:
            return

        proto = PROTOS.get(packet[IP].proto, str(packet[IP].proto))

        # Save to Database
        cursor.execute(
            "INSERT INTO packets (source, destination, protocol) VALUES (?, ?, ?)",
            (src, dst, proto),
        )
        conn.commit()

        try:
            packet_queue.put_nowait((src, dst, proto))
        except queue.Full:
            pass


def update_gui():
    batch_count = 0
    while not packet_queue.empty() and batch_count < 50:
        item = packet_queue.get_nowait()
        if isinstance(item, tuple):
            src, dst, proto = item
            proto_count[proto] += 1
            log_text.insert(
                tk.END,
                f"Source: {src} | Destination: {dst} | Protocol: {proto}\n",
            )
        else:
            log_text.insert(tk.END, item)
        batch_count += 1

    lines = int(log_text.index("end-1c").split(".")[0])
    if lines > 1000:
        log_text.delete("1.0", f"{lines - 1000}.0")

    log_text.see(tk.END)
    root.after(100, update_gui)


def update_chart():
    ax.clear()
    if proto_count:
        keys = list(proto_count.keys())
        values = list(proto_count.values())
        colors = ["#4c78a8", "#f58518", "#54a24b", "#e45756"]
        ax.bar(keys, values, color=colors[: len(keys)])

    ax.set_title("Packets by Protocol", fontsize=12, fontweight="bold")
    ax.set_ylabel("Count")
    canvas.draw_idle()
    root.after(1000, update_chart)


def clear_logs():
    log_text.delete("1.0", tk.END)


def reset_chart():
    proto_count.clear()
    ax.clear()
    ax.set_title("Packets by Protocol", fontsize=12, fontweight="bold")
    ax.set_ylabel("Count")
    canvas.draw_idle()


def load_history():
    for row in history_tree.get_children():
        history_tree.delete(row)

    cursor.execute("SELECT source, destination, protocol FROM packets")
    rows = cursor.fetchall()
    for row in rows:
        history_tree.insert("", tk.END, values=row)


def add_blocked_ip():
    ip = ip_entry.get().strip()
    if ip:
        BLOCKED_IPS.add(ip)
        ip_entry.delete(0, tk.END)
        status_label.config(text=f"Blocked: {ip}", fg="red")
        root.after(2000, lambda: status_label.config(text="", fg="green"))


def start_sniffing():
    try:
        sniff(
            filter="ip",
            prn=packet_callback,
            store=False,
            stop_filter=lambda x: stop_sniffing_event.is_set(),
        )
    except Exception as e:
        packet_queue.put(f"ERROR: {e}\n")


def on_closing():
    stop_sniffing_event.set()
    conn.close()
    root.destroy()


# GUI Setup
root = tk.Tk()
root.title("Advanced Packet Analyzer & Firewall Dashboard")
root.geometry("1400x700")
root.config(bg="#f0f0f0")

# Left Column (Logs, Controls, History)
left_frame = tk.Frame(root, bg="#f0f0f0")
left_frame.pack(side="left", fill="both", expand=True, padx=10, pady=10)

# Live Logs
log_label = tk.Label(left_frame, text="Live Traffic Logs", bg="#f0f0f0")
log_label.pack(anchor="w")
log_text = tk.Text(
    left_frame,
    height=15,
    width=60,
    font=("Consolas", 9),
    bg="#1e1e1e",
    fg="#00ff00",
)
log_text.pack(fill="both", expand=True, pady=(0, 10))

# Control Buttons
btn_frame = tk.Frame(left_frame, bg="#f0f0f0")
btn_frame.pack(fill="x", pady=(0, 10))

clear_btn = tk.Button(
    btn_frame,
    text="Clear Logs",
    command=clear_logs,
    bg="#e1e1e1",
    padx=10,
    pady=5,
)
clear_btn.pack(side="left", padx=5)

reset_btn = tk.Button(
    btn_frame,
    text="Reset Graph",
    command=reset_chart,
    bg="#e1e1e1",
    padx=10,
    pady=5,
)
reset_btn.pack(side="left", padx=5)

history_btn = tk.Button(
    btn_frame,
    text="Load History",
    command=load_history,
    bg="#e1e1e1",
    padx=10,
    pady=5,
    relief="raised",
)
history_btn.pack(side="left", padx=5)

# Firewall Controls
ip_frame = tk.Frame(left_frame, bg="#f0f0f0")
ip_frame.pack(fill="x", pady=(0, 10))

ip_label = tk.Label(ip_frame, text="Block IP Address:", bg="#f0f0f0")
ip_label.pack(side="left")

ip_entry = tk.Entry(ip_frame, width=15)
ip_entry.pack(side="left", padx=5)

block_btn = tk.Button(
    ip_frame, text="Block", command=add_blocked_ip, bg="#ffcccc", padx=5
)
block_btn.pack(side="left")

status_label = tk.Label(left_frame, text="", bg="#f0f0f0")
status_label.pack(anchor="w")

# History Treeview
history_label = tk.Label(left_frame, text="Database History", bg="#f0f0f0")
history_label.pack(anchor="w")

columns = ("source", "destination", "protocol")
history_tree = ttk.Treeview(
    left_frame, columns=columns, show="headings", height=12
)
history_tree.heading("source", text="Source")
history_tree.heading("destination", text="Destination")
history_tree.heading("protocol", text="Protocol")
history_tree.pack(fill="both", expand=True)

# Right Column (Matplotlib Chart)
right_frame = tk.Frame(root, bg="#f0f0f0")
right_frame.pack(side="right", fill="both", expand=True, padx=10, pady=10)

fig = Figure(figsize=(6, 5), dpi=100)
ax = fig.add_subplot(111)
canvas = FigureCanvasTkAgg(fig, master=right_frame)
canvas.get_tk_widget().pack(fill="both", expand=True)

threading.Thread(target=start_sniffing, daemon=True).start()

root.protocol("WM_DELETE_WINDOW", on_closing)
root.after(100, update_gui)
root.after(1000, update_chart)
root.mainloop()
