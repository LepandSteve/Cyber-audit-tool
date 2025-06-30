
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

def show_port_chart(report_text):
    import re
    from collections import Counter

    ports = re.findall(r'Open port: (\d+)', report_text)
    if not ports:
        return

    port_counts = Counter(ports)
    ports = list(port_counts.keys())
    counts = list(port_counts.values())

    fig, ax = plt.subplots(figsize=(6, 4))
    ax.bar(ports, counts, color='skyblue')
    ax.set_title("Open Port Distribution")
    ax.set_xlabel("Port")
    ax.set_ylabel("Count")

    plt.tight_layout()
    plt.show()
