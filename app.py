# app.py
import streamlit as st
st.set_page_config(page_title="Network Traffic Analyzer", layout="wide")
import pandas as pd
import io
import time
from pathlib import Path
from datetime import datetime

# import analyzer functions (expects analyzer/traffic_analyzer.py present)
from analyzer.traffic_analyzer import (
    main as analyze_traffic,
    get_protocol_distribution as _get_proto_df_helper,  # optional fallback
)

# Constants
DEFAULT_PCAP = "data/fake_attack.pcap"
LOGO_PATH = "/mnt/data/06f03cbb-49be-42ad-aa18-440684167dfd.png"  # uploaded file in session history

st.set_page_config(page_title="Network Traffic Analyzer", layout="wide")

# Header
with st.container():
    cols = st.columns([1, 4])
    with cols[0]:
        if Path(LOGO_PATH).exists():
            st.image(LOGO_PATH, width=120)
        else:
            st.write("")  # no logo found
    with cols[1]:
        st.title("Network Traffic Analyzer")
        st.markdown("**Live + PCAP + AI Insights** — Upload a PCAP or use the sample to analyze traffic, visualize top talkers, ports and detect anomalies.")

# Sidebar controls
st.sidebar.header("Controls")
uploaded_file = st.sidebar.file_uploader("Upload PCAP file", type=["pcap", "pcapng"])
use_sample = st.sidebar.button("Use sample PCAP (fake_attack.pcap)")
mode = st.sidebar.selectbox("Mode", ["Quick Summary", "Protocol Analysis", "Attack Detection", "AI Insights"])
visualize = st.sidebar.checkbox("Show Visualizations", value=True)
simulate_live = st.sidebar.checkbox("Simulate Live Replay (packet-by-packet)")
replay_delay = st.sidebar.slider("Replay delay (seconds per packet)", min_value=0.01, max_value=1.0, value=0.05, step=0.01)
export_format = st.sidebar.selectbox("Export results format", options=["none", "csv", "json"])
packet_count = st.sidebar.number_input("Live capture packet count (if capturing live)", min_value=1, max_value=10000, value=200, step=1)

analyze_button = st.sidebar.button("Analyze")

# Helper: display small metric cards
def metric_card(col, label, value, delta=None):
    if delta is None:
        col.metric(label, value)
    else:
        col.metric(label, value, delta)

# Simple rule-based AI summary generator
def generate_ai_summary(protocol_df, ip_comm_table, port_df):
    messages = []
    score = 0

    # protocol insights
    if protocol_df is not None and not protocol_df.empty:
        top_proto = protocol_df.iloc[0]
        messages.append(f"Top protocol: **{top_proto['Protocol']}** ({top_proto['Percentage']:.1f}%).")
        if top_proto["Protocol"] in ("UDP", "ICMP") and top_proto["Percentage"] > 40:
            messages.append(f"High share of {top_proto['Protocol']} suggests possible volumetric activity.")
            score += 30
        if top_proto["Protocol"] == "TCP" and top_proto["Percentage"] > 70:
            messages.append("Mostly TCP traffic — could be normal web/ssh activity or targeted TCP flows.")
            score += 5

    # top talker
    if ip_comm_table is not None and not ip_comm_table.empty:
        top = ip_comm_table.iloc[0]
        src = top["Source IP"]
        dst = top["Destination IP"]
        cnt = top["Count"]
        messages.append(f"Top talker: **{src} → {dst}** with **{cnt} packets**.")
        if cnt > 30:
            messages.append("This flow's packet count is unusually high — possible flood or prolonged transfer.")
            score += 30
        elif cnt > 10:
            score += 10

    # port anomalies
    if port_df is not None and not port_df.empty:
        top_port = port_df.iloc[0]
        p = top_port["Port"]
        c = top_port["Count"]
        messages.append(f"Top targeted port: **{p}** with **{c} packets**.")
        if "TCP" in str(p) and c > 20:
            messages.append("Multiple packets to the same TCP port may indicate scanning or targeted attempts.")
            score += 15

    # final risk score clamp and short conclusion
    score = max(0, min(100, score))
    conclusion = "Low" if score < 30 else "Medium" if score < 70 else "High"
    return {
        "summary": " ".join(messages) if messages else "No significant observations.",
        "score": score,
        "conclusion": conclusion
    }

# Convert DataFrame to downloadable content
def df_to_download_bytes(df, fmt="csv"):
    if df is None or df.empty:
        return None
    if fmt == "csv":
        return df.to_csv(index=False).encode("utf-8")
    else:  # json
        return df.to_json(orient="records").encode("utf-8")

# Main analysis runner
def run_analysis(pcap_path=None, live=False, pkt_count=100, do_visualize=True, export=None, simulate=False, delay=0.05):
    # call analyzer.main -> returns a tuple or None
    results = analyze_traffic(pcap_path, threshold=None, export_format=None, visualize=False, live_mode=live, packet_count=pkt_count)
    if results is None:
        st.error("No packets were loaded / analysis failed.")
        return None

    total_bw, protocol_df, ip_comm_table, ip_protocols, port_df = results

    # display top metrics
    col1, col2, col3, col4 = st.columns(4)
    unit = "KB" if total_bw < 1e6 else "MB"
    bw = total_bw / 1e3 if unit == "KB" else total_bw / 1e6
    metric_card(col1, "Total Bandwidth", f"{bw:.2f} {unit}")
    metric_card(col2, "Total Packets", len(protocol_df["Protocol"].sum() * 0) if protocol_df is None else int(protocol_df["Count"].sum()))
    metric_card(col3, "Unique Flows", f"{len(ip_comm_table)}")
    # compute quick threats count heuristic
    threats_est = 0
    if not ip_comm_table.empty:
        if ip_comm_table["Count"].max() > 30:
            threats_est += 1
    if protocol_df is not None and not protocol_df.empty:
        if (protocol_df["Protocol"] == "ARP").any() and protocol_df.loc[protocol_df["Protocol"]=="ARP","Count"].iloc[0] > 5:
            threats_est += 1
    metric_card(col4, "Estimated Threats", str(threats_est))

    # visualizations
    if do_visualize:
        left_col, right_col = st.columns([2,1])
        with left_col:
            st.subheader("Protocol Distribution")
            if protocol_df is not None and not protocol_df.empty:
                st.pyplot(_plot_protocol_pie(protocol_df))
            else:
                st.write("No protocol data.")

            st.subheader("Top IP Communications")
            if ip_comm_table is not None and not ip_comm_table.empty:
                st.bar_chart(_bar_top_ip_comm(ip_comm_table))
            else:
                st.write("No IP communications.")

        with right_col:
            st.subheader("Top Ports")
            if port_df is not None and not port_df.empty:
                st.pyplot(_plot_port_bar(port_df))
            else:
                st.write("No port data.")

            st.subheader("Protocol-by-Flow (sample)")
            if ip_protocols is not None and not ip_protocols.empty:
                st.dataframe(ip_protocols.head(10))
            else:
                st.write("No data.")

    # generate AI summary
    ai = generate_ai_summary(protocol_df, ip_comm_table, port_df)
    st.subheader("AI Insights")
    st.metric("Risk score", f"{ai['score']}/100", delta=ai['conclusion'])
    st.write(ai["summary"])

    # detailed tables
    with st.expander("Show full protocol distribution"):
        if protocol_df is not None and not protocol_df.empty:
            st.dataframe(protocol_df)
        else:
            st.write("No protocol distribution data.")

    with st.expander("Show IP communications (top 100)"):
        if ip_comm_table is not None and not ip_comm_table.empty:
            st.dataframe(ip_comm_table.head(100))
        else:
            st.write("No IP communications.")

    # export buttons
    st.subheader("Export Results")
    if export and export != "none":
        proto_bytes = df_to_download_bytes(protocol_df, export)
        ip_bytes = df_to_download_bytes(ip_comm_table, export)
        if proto_bytes:
            st.download_button("Download protocol distribution", data=proto_bytes, file_name=f"protocol_distribution.{export}", mime="text/csv" if export=="csv" else "application/json")
        if ip_bytes:
            st.download_button("Download ip communications", data=ip_bytes, file_name=f"ip_communications.{export}", mime="text/csv" if export=="csv" else "application/json")

    # simulated replay if requested
    if simulate:
        st.subheader("Simulated Live Replay")
        st.info("Replaying packets from the PCAP one-by-one. Close this message to stop.")
        _simulate_replay(pcap_path, delay)

    return {
        "total_bw": total_bw,
        "protocol_df": protocol_df,
        "ip_comm_table": ip_comm_table,
        "ip_protocols": ip_protocols,
        "port_df": port_df,
        "ai": ai
    }

# plotting helpers (use matplotlib but do not set explicit colors)
import matplotlib.pyplot as plt
def _plot_protocol_pie(protocol_df):
    fig, ax = plt.subplots(figsize=(5,5))
    ax.pie(protocol_df["Count"], labels=protocol_df["Protocol"], autopct="%1.1f%%")
    ax.set_title("Protocol Distribution")
    plt.tight_layout()
    return fig

def _bar_top_ip_comm(ip_comm_table):
    # return a DataFrame suitable for st.bar_chart
    top = ip_comm_table.head(10).copy()
    labels = top["Source IP"] + " → " + top["Destination IP"]
    df = pd.DataFrame({"count": top["Count"].values}, index=labels)
    return df

def _plot_port_bar(port_df):
    fig, ax = plt.subplots(figsize=(6,3))
    ax.bar(port_df["Port"].astype(str), port_df["Count"])
    ax.set_title("Top Ports")
    ax.set_xlabel("Port")
    ax.set_ylabel("Count")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    return fig

# simulate replay — simple loop updating a small status area
from scapy.all import rdpcap
def _simulate_replay(pcap_path, delay=0.05):
    if not pcap_path or not Path(pcap_path).exists():
        st.warning("No PCAP available for replay.")
        return
    packets = rdpcap(pcap_path)
    status = st.empty()
    progress = st.progress(0)
    total = len(packets)
    for i, pkt in enumerate(packets):
        status.markdown(f"Replaying packet **{i+1}/{total}** — {pkt.summary()}")
        progress.progress(int(((i+1)/total)*100))
        time.sleep(delay)
    status.success("Replay finished.")
    progress.empty()

# handle user interactions
pcap_to_use = None
if use_sample:
    pcap_to_use = DEFAULT_PCAP

if uploaded_file is not None:
    # save uploaded file to a temporary path
    tmp_path = Path("data") / f"uploaded_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
    tmp_path.parent.mkdir(parents=True, exist_ok=True)
    with open(tmp_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    pcap_to_use = str(tmp_path)
    st.success(f"Saved uploaded file to {tmp_path}")

# Analyze button pressed
if analyze_button:
    if not pcap_to_use:
        st.warning("No PCAP selected. Either upload one or use the sample PCAP.")
    else:
        with st.spinner("Running analysis..."):
            results = run_analysis(
                pcap_path=pcap_to_use,
                live=False,
                pkt_count=packet_count,
                do_visualize=visualize,
                export=export_format,
                simulate=simulate_live,
                delay=replay_delay
            )
        st.success("Analysis complete.")
