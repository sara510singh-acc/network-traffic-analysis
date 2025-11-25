# main.py
from analyzer.traffic_analyzer import main as analyze_traffic, print_results
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Traffic Analyzer")
    parser.add_argument("pcap_file", nargs="?", help="Path to the PCAP file (optional in live mode)")
    parser.add_argument("--threshold", type=int, default=50, help="Port scan detection threshold (currently unused)")
    parser.add_argument("--export", choices=["csv", "json"], help="Export results format")
    parser.add_argument("--visualize", action="store_true", help="Show charts for analysis")
    parser.add_argument("--live", action="store_true", help="Capture live traffic")
    parser.add_argument("--count", type=int, default=100, help="Number of packets to capture in live mode")
    args = parser.parse_args()

    results = analyze_traffic(
        args.pcap_file if not args.live else None,
        threshold=args.threshold,
        export_format=args.export,
        visualize=args.visualize,
        live_mode=args.live,
        packet_count=args.count
    )

    if results is None:
        print("No results returned from analyzer.")
    else:
        total_bw, protocol_df, ip_comm_table, ip_protocols, port_df = results
        print_results(total_bw, protocol_df, ip_comm_table, ip_protocols)
