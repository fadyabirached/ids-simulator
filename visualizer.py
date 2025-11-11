

import matplotlib.pyplot as plt

def plot_top_counts(counter, title, top_n=10, malicious_ips=None):
   
    malicious_ips = malicious_ips or set()

    items = sorted(counter.items(), key=lambda kv: kv[1], reverse=True)[:top_n]
    keys = [str(k) for k, _ in items]
    values = [v for _, v in items]

    plt.style.use("dark_background")
    fig, ax = plt.subplots(figsize=(9, 5))
    fig.patch.set_facecolor("#1e1e1e")
    ax.set_facecolor("#111")

    bar_colors = []
    for k in keys:
        if k in malicious_ips:
            bar_colors.append("#ff5555")  
        else:
            bar_colors.append("#00ff99")  

    bars = ax.barh(keys, values, color=bar_colors, edgecolor="#00c8ff", linewidth=1.3)

    ax.set_title(title, fontsize=16, color="#00c8ff", pad=15, weight="bold")
    ax.set_xlabel("Event Count", fontsize=12, color="#cccccc")
    ax.set_ylabel("IP / Port", fontsize=12, color="#cccccc")

    ax.grid(True, color="#333333", linestyle="--", linewidth=0.5)
    ax.tick_params(colors="#dddddd", labelsize=10)
    ax.invert_yaxis()

    for bar in bars:
        width = bar.get_width()
        ax.text(width + 0.5, bar.get_y() + bar.get_height() / 2,
                f"{int(width)}", va="center", ha="left", color="#ffffff", fontsize=9)

    plt.tight_layout()
    plt.show()
