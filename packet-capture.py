# # from scapy.all import *
# # from collections import defaultdict
# # import time
# # import statistics
# # from tabulate import tabulate
# # import csv

# # # Data structure to store flow statistics
# # flows = defaultdict(lambda: {
# #     'duration': 0,
# #     'total_fwd_packets': 0,
# #     'total_bwd_packets': 0,
# #     'total_length_fwd_packets': 0,
# #     'total_length_bwd_packets': 0,
# #     'fwd_packet_lengths': [],
# #     'bwd_packet_lengths': [],
# #     'fwd_iat': [],
# #     'bwd_iat': [],
# #     'fwd_flags': {'PSH': 0, 'URG': 0},
# #     'bwd_flags': {'PSH': 0, 'URG': 0},
# #     'flow_start_time': None,
# #     'last_fwd_time': None,
# #     'last_bwd_time': None
# # })

# # # Helper function to compute IAT
# # def compute_iat(last_time, current_time):
# #     if last_time is None:
# #         return 0
# #     return current_time - last_time

# # # Packet callback function
# # def packet_callback(packet):
# #     # Skip if not IP packet
# #     if not packet.haslayer(IP):
# #         return

# #     ip_layer = packet[IP]
# #     src_ip = ip_layer.src
# #     dst_ip = ip_layer.dst

# #     # Determine if forward or backward packet
# #     if packet.haslayer(TCP):
# #         proto = "TCP"
# #         src_port = packet[TCP].sport
# #         dst_port = packet[TCP].dport
# #         flags = packet[TCP].flags
# #         length = len(packet[TCP])
# #     elif packet.haslayer(UDP):
# #         proto = "UDP"
# #         src_port = packet[UDP].sport
# #         dst_port = packet[UDP].dport
# #         length = len(packet[UDP])
# #         flags = None
# #     else:
# #         return

# #     # Flow key
# #     flow_key = (src_ip, dst_ip, src_port, dst_port, proto)

# #     # Initialize flow
# #     if flows[flow_key]['flow_start_time'] is None:
# #         flows[flow_key]['flow_start_time'] = packet.time

# #     # Check if it's a forward or backward packet
# #     if (src_ip, src_port) == (flow_key[0], flow_key[2]):
# #         # Forward packet
# #         flows[flow_key]['total_fwd_packets'] += 1
# #         flows[flow_key]['total_length_fwd_packets'] += length
# #         flows[flow_key]['fwd_packet_lengths'].append(length)
# #         # if flows[flow_key]['last_fwd_time'] is not None:
# #         flows[flow_key]['fwd_iat'].append(compute_iat(flows[flow_key]['last_fwd_time'], packet.time))
# #         flows[flow_key]['last_fwd_time'] = packet.time
# #         if flags and 'P' in flags:
# #             flows[flow_key]['fwd_flags']['PSH'] += 1
# #         if flags and 'U' in flags:
# #             flows[flow_key]['fwd_flags']['URG'] += 1
# #     elif (src_ip, src_port) == (flow_key[1], flow_key[3]):
# #         # Backward packet
# #         flows[flow_key]['total_bwd_packets'] += 1
# #         flows[flow_key]['total_length_bwd_packets'] += length
# #         flows[flow_key]['bwd_packet_lengths'].append(length)
        
# #         flows[flow_key]['bwd_iat'].append(compute_iat(flows[flow_key]['last_bwd_time'], packet.time))
# #         flows[flow_key]['last_bwd_time'] = packet.time
# #         if flags and 'P' in flags:
# #             flows[flow_key]['bwd_flags']['PSH'] += 1
# #         if flags and 'U' in flags:
# #             flows[flow_key]['bwd_flags']['URG'] += 1

# # # Sniff packets
# # sniff(iface="Wi-Fi", prn=packet_callback, count=100)
# # table_data = []

# # # Compute final statistics
# # for flow_key, stats in flows.items():
# #     src_ip, dst_ip, src_port, dst_port, proto = flow_key
# #     stats['duration'] = time.time() - stats['flow_start_time']
# #     stats['flow_bytes_per_sec'] = (stats['total_length_fwd_packets'] + stats['total_length_bwd_packets']) / stats['duration']
# #     stats['flow_packets_per_sec'] = (stats['total_fwd_packets'] + stats['total_bwd_packets']) / stats['duration']

# #     # Forward and backward packet statistics
# #     if stats['fwd_packet_lengths']:
# #         stats['fwd_packet_length_max'] = max(stats['fwd_packet_lengths'])
# #         stats['fwd_packet_length_min'] = min(stats['fwd_packet_lengths'])
# #         stats['fwd_packet_length_mean'] = sum(stats['fwd_packet_lengths']) / len(stats['fwd_packet_lengths'])
# #         stats['fwd_packet_length_std'] = (sum((x - stats['fwd_packet_length_mean']) ** 2 for x in stats['fwd_packet_lengths']) / len(stats['fwd_packet_lengths'])) ** 0.5

# #     if stats['bwd_packet_lengths']:
# #         stats['bwd_packet_length_max'] = max(stats['bwd_packet_lengths'])
# #         stats['bwd_packet_length_min'] = min(stats['bwd_packet_lengths'])
# #         stats['bwd_packet_length_mean'] = sum(stats['bwd_packet_lengths']) / len(stats['bwd_packet_lengths'])
# #         stats['bwd_packet_length_std'] = (sum((x - stats['bwd_packet_length_mean']) ** 2 for x in stats['bwd_packet_lengths']) / len(stats['bwd_packet_lengths'])) ** 0.5

# #     # Flow IAT statistics
# #     if len(stats['fwd_iat']) > 1:
# #         stats['fwd_iat_mean'] = sum(stats['fwd_iat']) / len(stats['fwd_iat'])
# #         stats['fwd_iat_std'] = statistics.stdev(stats['fwd_iat'])
# #         stats['fwd_iat_max'] = max(stats['fwd_iat'])
# #         stats['fwd_iat_min'] = min(stats['fwd_iat'])
# #     else:
# #         stats['fwd_iat_mean'] = 0
# #         stats['fwd_iat_std'] = 0
# #         stats['fwd_iat_max'] = 0
# #         stats['fwd_iat_min'] = 0

# #     if len(stats['bwd_iat']) > 1:
# #         stats['bwd_iat_mean'] = sum(stats['bwd_iat']) / len(stats['bwd_iat'])
# #         stats['bwd_iat_std'] = statistics.stdev(stats['bwd_iat'])
# #         stats['bwd_iat_max'] = max(stats['bwd_iat'])
# #         stats['bwd_iat_min'] = min(stats['bwd_iat'])
# #     else:
# #         stats['bwd_iat_mean'] = 0
# #         stats['bwd_iat_std'] = 0
# #         stats['bwd_iat_max'] = 0
# #         stats['bwd_iat_min'] = 0

# #     # Print flow statistics
# #     table_data.append([
# #         src_ip,
# #         src_port,
# #         dst_ip,
# #         dst_port,
# #         proto,
# #         f"{stats['duration']:.2f}s",
# #         stats['total_fwd_packets'],
# #         stats['total_bwd_packets'],
# #         stats['total_length_fwd_packets'],
# #         stats['total_length_bwd_packets'],
# #         f"{stats.get('fwd_packet_length_mean', 0):.2f}",
# #         f"{stats.get('fwd_packet_length_std', 0):.2f}",
# #         f"{stats.get('bwd_packet_length_mean', 0):.2f}",
# #         f"{stats.get('bwd_packet_length_std', 0):.2f}",
# #         f"{stats['flow_bytes_per_sec']:.2f}",
# #         f"{stats['flow_packets_per_sec']:.2f}",
# #         f"{stats.get('fwd_iat_mean', 0):.2f}",
# #         f"{stats.get('fwd_iat_std', 0):.2f}",
# #         f"{stats.get('fwd_iat_max', 0):.2f}",
# #         f"{stats.get('fwd_iat_min', 0):.2f}",
# #         f"{stats.get('bwd_iat_mean', 0):.2f}",
# #         f"{stats.get('bwd_iat_std', 0):.2f}",
# #         f"{stats.get('bwd_iat_max', 0):.2f}",
# #         f"{stats.get('bwd_iat_min', 0):.2f}",
# #         stats['fwd_flags']['PSH'],
# #         stats['bwd_flags']['PSH'],
# #         stats['fwd_flags']['URG'],
# #         stats['bwd_flags']['URG']
# #     ])

# # headers = [
# #     "Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol",
# #     "Duration", "Total Fwd Packets", "Total Bwd Packets", "Total Length Fwd Packets",
# #     "Total Length Bwd Packets", "Fwd Packet Length Mean", "Fwd Packet Length Std",
# #     "Bwd Packet Length Mean", "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s",
# #     "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Mean",
# #     "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags",
# #     "Fwd URG Flags", "Bwd URG Flags"
# # ]
# # with open('flow_statistics.csv', 'w', newline='') as csvfile:
# #     csvwriter = csv.writer(csvfile)
# #     csvwriter.writerow(headers)
# #     csvwriter.writerows(table_data)
# # # print(tabulate(table_data, headers=headers, tablefmt="grid"))
# #     # print(f"Flow: {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({proto})")
# #     # print(f"  Duration: {stats['duration']:.2f}s")
# #     # print(f"  Total Forward Packets: {stats['total_fwd_packets']}")
# #     # print(f"  Total Backward Packets: {stats['total_bwd_packets']}")
# #     # print(f"  Total Length of Forward Packets: {stats['total_length_fwd_packets']}")
# #     # print(f"  Total Length of Backward Packets: {stats['total_length_bwd_packets']}")
# #     # print(f"  Forward Packet Length Mean: {stats.get('fwd_packet_length_mean', 0):.2f}")
# #     # print(f"  Forward Packet Length Std: {stats.get('fwd_packet_length_std', 0):.2f}")
# #     # print(f"  Backward Packet Length Mean: {stats.get('bwd_packet_length_mean', 0):.2f}")
# #     # print(f"  Backward Packet Length Std: {stats.get('bwd_packet_length_std', 0):.2f}")
# #     # print(f"  Flow Bytes/s: {stats['flow_bytes_per_sec']:.2f}")
# #     # print(f"  Flow Packets/s: {stats['flow_packets_per_sec']:.2f}")
# #     # print(f"  Forward PSH Flags: {stats['fwd_flags']['PSH']}")
# #     # print(f"  Backward PSH Flags: {stats['bwd_flags']['PSH']}")
# #     # print(f"  Forward URG Flags: {stats['fwd_flags']['URG']}")
# #     # print(f"  Backward URG Flags: {stats['bwd_flags']['URG']}")
# #     # print(f"  Flow IAT Mean (Forward): {stats.get('fwd_iat_mean', 0):.8f}")
# #     # print(f"  Flow IAT Std (Forward): {stats.get('fwd_iat_std', 0):.2f}")
# #     # print(f"  Flow IAT Max (Forward): {stats.get('fwd_iat_max', 0):.8f}")
# #     # print(f"  Flow IAT Min (Forward): {stats.get('fwd_iat_min', 0):.2f}")
# #     # print(f"  Flow IAT Mean (Backward): {stats.get('bwd_iat_mean', 0):.2f}")
# #     # print(f"  Flow IAT Std (Backward): {stats.get('bwd_iat_std', 0):.2f}")
# #     # print(f"  Flow IAT Max (Backward): {stats.get('bwd_iat_max', 0):.2f}")
# #     # print(f"  Flow IAT Min (Backward): {stats.get('bwd_iat_min', 0):.2f}")
# #     # print(stats['fwd_iat'])
# # print("-" * 80)





# ******************************* MAIN

# **********************

# ********
# from scapy.all import *
# from collections import defaultdict
# import time
# import statistics
# import csv

# # Data structure to store flow statistics
# flows = defaultdict(lambda: {
#     'duration': 0,
#     'total_fwd_packets': 0,
#     'total_bwd_packets': 0,
#     'total_length_fwd_packets': 0,
#     'total_length_bwd_packets': 0,
#     'fwd_packet_lengths': [0],
#     'bwd_packet_lengths': [0],
#     'fwd_iat': [0],
#     'bwd_iat': [0],
#     'fwd_flags': {'PSH': 0, 'URG': 0},
#     'bwd_flags': {'PSH': 0, 'URG': 0},
#     'flow_start_time': None,
#     'last_fwd_time': None,
#     'last_bwd_time': None,
#     'fwd_header_lengths': [0],
#     'bwd_header_lengths': [0],
#     'packet_lengths': [0],
#     'fin_flags': 0,
#     'syn_flags': 0,
#     'rst_flags': 0,
#     'psh_flags': 0,
#     'ack_flags': 0,
#     'urg_flags': 0,
#     'cwe_flags': 0,
#     'ece_flags': 0,
#     'subflow_fwd_packets': 0,
#     'subflow_fwd_bytes': 0,
#     'subflow_bwd_packets': 0,
#     'subflow_bwd_bytes': 0,
#     'init_win_bytes_forward': 0,
#     'init_win_bytes_backward': 0,
#     'active_times': [0],
#     'idle_times': [0]
# })

# # Helper function to compute IAT
# def compute_iat(last_time, current_time):
#     if last_time is None:
#         return 0
#     return current_time - last_time

# # Packet callback function
# def packet_callback(packet):
#     # Skip if not IP packet
#     if not packet.haslayer(IP):
#         return

#     ip_layer = packet[IP]
#     src_ip = ip_layer.src
#     dst_ip = ip_layer.dst

#     # Determine if forward or backward packet
#     if packet.haslayer(TCP):
#         proto = "TCP"
#         src_port = packet[TCP].sport
#         dst_port = packet[TCP].dport
#         flags = packet[TCP].flags
#         length = len(packet[TCP])
#         header_length = packet[TCP].dataofs * 4
#         fin_flag = int(flags & 0x01 != 0)
#         syn_flag = int(flags & 0x02 != 0)
#         rst_flag = int(flags & 0x04 != 0)
#         psh_flag = int(flags & 0x08 != 0)
#         ack_flag = int(flags & 0x10 != 0)
#         urg_flag = int(flags & 0x20 != 0)
#         cwe_flag = int(flags & 0x40 != 0)
#         ece_flag = int(flags & 0x80 != 0)
#     elif packet.haslayer(UDP):
#         proto = "UDP"
#         src_port = packet[UDP].sport
#         dst_port = packet[UDP].dport
#         length = len(packet[UDP])
#         header_length = 8  # UDP header length is 8 bytes
#         fin_flag = syn_flag = rst_flag = psh_flag = ack_flag = urg_flag = cwe_flag = ece_flag = 0
#     else:
#         return

#     # Flow key
#     flow_key = (src_ip, dst_ip, src_port, dst_port, proto)

#     # Initialize flow
#     if flows[flow_key]['flow_start_time'] is None:
#         flows[flow_key]['flow_start_time'] = packet.time

#     # Check if it's a forward or backward packet
#     if (src_ip, src_port) == (flow_key[0], flow_key[2]):
#         # Forward packet
#         flows[flow_key]['total_fwd_packets'] += 1
#         flows[flow_key]['total_length_fwd_packets'] += length
#         flows[flow_key]['fwd_packet_lengths'].append(length)
#         flows[flow_key]['fwd_header_lengths'].append(header_length)
#         flows[flow_key]['subflow_fwd_packets'] += 1
#         flows[flow_key]['subflow_fwd_bytes'] += length
#         flows[flow_key]['fwd_iat'].append(compute_iat(flows[flow_key]['last_fwd_time'], packet.time))
#         flows[flow_key]['last_fwd_time'] = packet.time
#         flows[flow_key]['fin_flags'] += fin_flag
#         flows[flow_key]['syn_flags'] += syn_flag
#         flows[flow_key]['rst_flags'] += rst_flag
#         flows[flow_key]['psh_flags'] += psh_flag
#         flows[flow_key]['ack_flags'] += ack_flag
#         flows[flow_key]['urg_flags'] += urg_flag
#         flows[flow_key]['cwe_flags'] += cwe_flag
#         flows[flow_key]['ece_flags'] += ece_flag
#     elif (src_ip, src_port) == (flow_key[1], flow_key[3]):
#         # Backward packet
#         flows[flow_key]['total_bwd_packets'] += 1
#         flows[flow_key]['total_length_bwd_packets'] += length
#         flows[flow_key]['bwd_packet_lengths'].append(length)
#         flows[flow_key]['bwd_header_lengths'].append(header_length)
#         flows[flow_key]['subflow_bwd_packets'] += 1
#         flows[flow_key]['subflow_bwd_bytes'] += length
#         flows[flow_key]['bwd_iat'].append(compute_iat(flows[flow_key]['last_bwd_time'], packet.time))
#         flows[flow_key]['last_bwd_time'] = packet.time

#     # Track active and idle times
#     if flows[flow_key]['last_fwd_time'] and flows[flow_key]['last_bwd_time']:
#         active_time = min(compute_iat(flows[flow_key]['last_bwd_time'], packet.time),
#                           compute_iat(flows[flow_key]['last_fwd_time'], packet.time))
#         idle_time = compute_iat(flows[flow_key]['last_bwd_time'], packet.time) - active_time
#         flows[flow_key]['active_times'].append(active_time)
#         flows[flow_key]['idle_times'].append(idle_time)

# # Sniff packets
# sniff(iface="Wi-Fi", prn=packet_callback, count=20)
# print("Start")
# sniff(iface="Wi-Fi", prn=packet_callback, count=20)

# # Prepare data for CSV
# csv_data = []
# headers = [
#     "Destination Port",
#     "Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets",
#     "Total Length of Bwd Packets", "Fwd Packet Length Mean", "Fwd Packet Length Max","Fwd Packet Length Min","Fwd Packet Length Std",
#     "Bwd Packet Length Mean","Bwd Packet Length Max","Bwd Packet Length Min", "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s",
#     "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Mean",
#     "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags",
#     "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length",
#     "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
#     "Packet Length Mean", "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
#     "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
#     "URG Flag Count", "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio",
#     "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
#     "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk",
#     "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk",
#     "Bwd Avg Bulk Rate", "Subflow Fwd Packets", "Subflow Fwd Bytes",
#     "Subflow Bwd Packets", "Subflow Bwd Bytes", "Init_Win_bytes_forward",
#     "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward",
#     "Active Mean", "Active Std", "Active Max", "Active Min", "Idle Mean",
#     "Idle Std", "Idle Max", "Idle Min"
# ]

# print("Headers length:", len(headers))

# print(len(headers))

# # Compute final statistics
# for flow_key, stats in flows.items():

#     src_ip, dst_ip, src_port, dst_port, proto = flow_key
#     if(src_ip=="192.168.14.147"):
#          print("yes")
#     stats['duration'] = time.time() - stats['flow_start_time']
#     stats['flow_bytes_per_sec'] = (stats['total_length_fwd_packets'] + stats['total_length_bwd_packets']) / stats['duration']
#     stats['flow_packets_per_sec'] = (stats['total_fwd_packets'] + stats['total_bwd_packets']) / stats['duration']

#     # Forward and backward packet statistics
#     if stats['fwd_packet_lengths']:
#         stats['fwd_packet_length_max'] = max(stats['fwd_packet_lengths'])
#         stats['fwd_packet_length_min'] = min(stats['fwd_packet_lengths'])
#         stats['fwd_packet_length_mean'] = sum(stats['fwd_packet_lengths']) / len(stats['fwd_packet_lengths'])
#         stats['fwd_packet_length_std'] = statistics.stdev(stats['fwd_packet_lengths'])
#     if len(stats['bwd_packet_lengths'])>1:
#         stats['bwd_packet_length_max'] = max(stats['bwd_packet_lengths'])
#         stats['bwd_packet_length_min'] = min(stats['bwd_packet_lengths'])
#         stats['bwd_packet_length_mean'] = sum(stats['bwd_packet_lengths']) / len(stats['bwd_packet_lengths'])
#         stats['bwd_packet_length_std'] = statistics.stdev(stats['bwd_packet_lengths'])

#     # Flow IAT statistics
#     if stats['fwd_iat']:
#         stats['fwd_iat_mean'] = sum(stats['fwd_iat']) / len(stats['fwd_iat'])
#         stats['fwd_iat_std'] = statistics.stdev(stats['fwd_iat'])
#         stats['fwd_iat_max'] = max(stats['fwd_iat'])
#         stats['fwd_iat_min'] = min(stats['fwd_iat'])
#     if len(stats['bwd_iat'])>1:
#         stats['bwd_iat_mean'] = sum(stats['bwd_iat']) / len(stats['bwd_iat'])
#         stats['bwd_iat_std'] = statistics.stdev(stats['bwd_iat'])
#         stats['bwd_iat_max'] = max(stats['bwd_iat'])
#         stats['bwd_iat_min'] = min(stats['bwd_iat'])

#     # Header lengths
#     if stats['fwd_header_lengths']:
#         stats['fwd_header_length_mean'] = sum(stats['fwd_header_lengths']) / len(stats['fwd_header_lengths'])
#     if stats['bwd_header_lengths']:
#         stats['bwd_header_length_mean'] = sum(stats['bwd_header_lengths']) / len(stats['bwd_header_lengths'])

#     # Packet lengths
#     if len(stats['packet_lengths'])>1:
#         stats['min_packet_length'] = min(stats['packet_lengths'])
#         stats['max_packet_length'] = max(stats['packet_lengths'])
#         stats['packet_length_mean'] = sum(stats['packet_lengths']) / len(stats['packet_lengths'])
#         stats['packet_length_std'] = statistics.stdev(stats['packet_lengths'])
#         stats['packet_length_variance'] = statistics.variance(stats['packet_lengths'])

#     # Flags
#     stats['fin_flag_count'] = stats['fin_flags']
#     stats['syn_flag_count'] = stats['syn_flags']
#     stats['rst_flag_count'] = stats['rst_flags']
#     stats['psh_flag_count'] = stats['psh_flags']
#     stats['ack_flag_count'] = stats['ack_flags']
#     stats['urg_flag_count'] = stats['urg_flags']
#     stats['cwe_flag_count'] = stats['cwe_flags']
#     stats['ece_flag_count'] = stats['ece_flags']

#     # Additional metrics
#     stats['down_up_ratio'] = stats['total_length_bwd_packets'] / (stats['total_length_fwd_packets'] + 1e-5)
#     stats['avg_packet_size'] = (stats['total_length_fwd_packets'] + stats['total_length_bwd_packets']) / (stats['total_fwd_packets'] + stats['total_bwd_packets'])
#     stats['avg_fwd_segment_size'] = stats['total_length_fwd_packets'] / (stats['total_fwd_packets'] + 1e-5)
#     stats['avg_bwd_segment_size'] = stats['total_length_bwd_packets'] / (stats['total_bwd_packets'] + 1e-5)
#     # stats['fwd_header_length_1'] = stats['fwd_header_length_mean']  # Assuming similar calculation
#     stats['fwd_avg_bytes_bulk'] = stats['total_length_fwd_packets'] / (stats['total_fwd_packets'] + 1e-5)
#     stats['fwd_avg_packets_bulk'] = stats['total_fwd_packets'] / (stats['total_fwd_packets'] + 1e-5)
#     stats['fwd_avg_bulk_rate'] = stats['fwd_avg_bytes_bulk'] / stats['duration']
#     stats['bwd_avg_bytes_bulk'] = stats['total_length_bwd_packets'] / (stats['total_bwd_packets'] + 1e-5)
#     stats['bwd_avg_packets_bulk'] = stats['total_bwd_packets'] / (stats['total_bwd_packets'] + 1e-5)
#     stats['bwd_avg_bulk_rate'] = stats['bwd_avg_bytes_bulk'] / stats['duration']
#     stats['subflow_fwd_packets'] = stats['subflow_fwd_packets']
#     stats['subflow_fwd_bytes'] = stats['subflow_fwd_bytes']
#     stats['subflow_bwd_packets'] = stats['subflow_bwd_packets']
#     stats['subflow_bwd_bytes'] = stats['subflow_bwd_bytes']
#     stats['init_win_bytes_forward'] = stats['init_win_bytes_forward']
#     stats['init_win_bytes_backward'] = stats['init_win_bytes_backward']
#     stats['act_data_pkt_fwd'] = stats['subflow_fwd_packets']
#     stats['min_seg_size_forward'] = min(stats['fwd_packet_lengths'] + [1e-5])
#     stats['active_mean'] = sum(stats['active_times']) / len(stats['active_times']) if stats['active_times'] else 0
#     stats['active_std'] = statistics.stdev(stats['active_times']) if len(stats['active_times']) > 1 else 0
#     stats['active_max'] = max(stats['active_times']) if stats['active_times'] else 0
#     stats['active_min'] = min(stats['active_times']) if stats['active_times'] else 0
#     stats['idle_mean'] = sum(stats['idle_times']) / len(stats['idle_times']) if stats['idle_times'] else 0
#     stats['idle_std'] = statistics.stdev(stats['idle_times']) if len(stats['idle_times']) > 1 else 0
#     stats['idle_max'] = max(stats['idle_times']) if stats['idle_times'] else 0
#     stats['idle_min'] = min(stats['idle_times']) if stats['idle_times'] else 0

#     # Append data to CSV list
    
#     csv_data.append([
#         # src_ip, src_p/ort, dst_ip, , proto,
        
#       dst_port,
#         stats['duration'],
#         stats['total_fwd_packets'],
#         stats['total_bwd_packets'],
#         stats['total_length_fwd_packets'], 
#         stats['total_length_bwd_packets'],
#         f"{stats.get('fwd_packet_length_mean', 0):.2f}",
#         f"{stats.get('fwd_packet_length_max', 0):.2f}",
#         f"{stats.get('fwd_packet_length_min', 0):.2f}",
#         f"{stats.get('fwd_packet_length_std', 0):.2f}",
#         f"{stats.get('bwd_packet_length_mean', 0):.2f}",
#         f"{stats.get('bwd_packet_length_max', 0):.2f}",
#         f"{stats.get('bwd_packet_length_min', 0):.2f}",
#         f"{stats.get('bwd_packet_length_std', 0):.2f}",
#         f"{stats.get('flow_bytes_per_sec', 0):.2f}",
#         f"{stats.get('flow_packets_per_sec', 0):.2f}",
#         f"{stats.get('fwd_iat_mean', 0):.2f}",
#         f"{stats.get('fwd_iat_std', 0):.2f}",
#         f"{stats.get('fwd_iat_max', 0):.2f}",
#         f"{stats.get('fwd_iat_min', 0):.2f}",
#         f"{stats.get('bwd_iat_mean', 0):.2f}",
#         f"{stats.get('bwd_iat_std', 0):.2f}",
#         f"{stats.get('bwd_iat_max', 0):.2f}",
#         f"{stats.get('bwd_iat_min', 0):.2f}",
#         stats['fwd_flags']['PSH'],
#         stats['bwd_flags']['PSH'],
#         stats['fwd_flags']['URG'],
#         stats['bwd_flags']['URG'],
#         # f"{stats.get('fwd_header_length_mean', 0):.2f}",
#         f"{stats.get('bwd_header_length_mean', 0):.2f}",
#         f"{stats.get('total_fwd_packets', 0) / (stats['duration'] + 1e-5):.2f}",
#         f"{stats.get('total_bwd_packets', 0) / (stats['duration'] + 1e-5):.2f}",
#         f"{stats.get('min_packet_length', 0):.2f}",
#         f"{stats.get('max_packet_length', 0):.2f}",
#         f"{stats.get('packet_length_mean', 0):.2f}",
#         f"{stats.get('packet_length_std', 0):.2f}",
#         f"{stats.get('packet_length_variance', 0):.2f}",
#         stats['fin_flag_count'],
#         stats['syn_flag_count'],
#         stats['rst_flag_count'],
#         stats['psh_flag_count'],
#         stats['ack_flag_count'],
#         stats['urg_flag_count'],
#         stats['cwe_flag_count'],
#         stats['ece_flag_count'],
#         f"{stats.get('down_up_ratio', 0):.2f}",
#         f"{stats.get('avg_packet_size', 0):.2f}",
#         f"{stats.get('avg_fwd_segment_size', 0):.2f}",
#         f"{stats.get('avg_bwd_segment_size', 0):.2f}",
#         f"{stats.get('fwd_header_length_mean', 0):.2f}",
#         f"{stats.get('fwd_avg_bytes_bulk', 0):.2f}",
#         f"{stats.get('fwd_avg_packets_bulk', 0):.2f}",
#         f"{stats.get('fwd_avg_bulk_rate', 0):.2f}",
#         f"{stats.get('bwd_avg_bytes_bulk', 0):.2f}",
#         f"{stats.get('bwd_avg_packets_bulk', 0):.2f}",
#         f"{stats.get('bwd_avg_bulk_rate', 0):.2f}",
#         stats['subflow_fwd_packets'],
#         stats['subflow_fwd_bytes'],
#         stats['subflow_bwd_packets'],
#         stats['subflow_bwd_bytes'],
#         stats['init_win_bytes_forward'],
#         stats['init_win_bytes_backward'],
#         stats['act_data_pkt_fwd'],
#         stats['min_seg_size_forward'],
#         f"{stats.get('active_mean', 0):.2f}",
#         f"{stats.get('active_std', 0):.2f}",
#         f"{stats.get('active_max', 0):.2f}",
#         f"{stats.get('active_min', 0):.2f}",
#         f"{stats.get('idle_mean', 0):.2f}",
#         f"{stats.get('idle_std', 0):.2f}",
#         f"{stats.get('idle_max', 0):.2f}",
#         f"{stats.get('idle_min', 0):.2f}"

#     ])
   



# # Write CSV file
# with open('network_flow_statistics_extended.csv', mode='w', newline='') as file:
#     writer = csv.writer(file)
#     writer.writerow(headers)
#     writer.writerows(csv_data)

# print("CSV file 'network_flow_statistics_extended.csv' has been created with additional parameters.")


# # *************
# # **********************
# # *******************************



 

from scapy.all import *
from collections import defaultdict
import time
import statistics
import csv


flows = defaultdict(lambda: {
    'duration': 0,
    'total_fwd_packets': 0,
    'total_bwd_packets': 0,
    'total_length_fwd_packets': 0,
    'total_length_bwd_packets': 0,
    'fwd_packet_lengths': [0],
    'bwd_packet_lengths': [0],
    'fwd_iat': [0],
    'bwd_iat': [0],
    'fwd_flags': {'PSH': 0, 'URG': 0},
    'bwd_flags': {'PSH': 0, 'URG': 0},
    'flow_start_time': None,
    'last_fwd_time': None,
    'last_bwd_time': None,
    'fwd_header_lengths': [0],
    'bwd_header_lengths': [0],
    'packet_lengths': [0],
    'fin_flags': 0,
    'syn_flags': 0,
    'rst_flags': 0,
    'psh_flags': 0,
    'ack_flags': 0,
    'urg_flags': 0,
    'cwe_flags': 0,
    'ece_flags': 0,
    'subflow_fwd_packets': 0,
    'subflow_fwd_bytes': 0,
    'subflow_bwd_packets': 0,
    'subflow_bwd_bytes': 0,
    'init_win_bytes_forward': 0,
    'init_win_bytes_backward': 0,
    'active_times': [0],
    'idle_times': [0]
})


def compute_iat(last_time, current_time):
    if last_time is None:
        return 0
    return current_time - last_time


def packet_callback(packet):
    
    if not packet.haslayer(IP):
        return

    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst

    # Determine if forward or backward packet
    if packet.haslayer(TCP):
        proto = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags
        length = len(packet[TCP])
        header_length = packet[TCP].dataofs * 4
        fin_flag = int(flags & 0x01 != 0)
        syn_flag = int(flags & 0x02 != 0)
        rst_flag = int(flags & 0x04 != 0)
        psh_flag = int(flags & 0x08 != 0)
        ack_flag = int(flags & 0x10 != 0)
        urg_flag = int(flags & 0x20 != 0)
        cwe_flag = int(flags & 0x40 != 0)
        ece_flag = int(flags & 0x80 != 0)
    elif packet.haslayer(UDP):
        proto = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        length = len(packet[UDP])
        header_length = 8  
        fin_flag = syn_flag = rst_flag = psh_flag = ack_flag = urg_flag = cwe_flag = ece_flag = 0
    else:
        return

    # Flow key
    flow_key = (src_ip, dst_ip, src_port, dst_port, proto)

    # Initialize flow
    if flows[flow_key]['flow_start_time'] is None:
        flows[flow_key]['flow_start_time'] = packet.time

    
    if (src_ip, src_port) == (flow_key[0], flow_key[2]):
        # Forward packet
        flows[flow_key]['total_fwd_packets'] += 1
        flows[flow_key]['total_length_fwd_packets'] += length
        flows[flow_key]['fwd_packet_lengths'].append(length)
        flows[flow_key]['fwd_header_lengths'].append(header_length)
        flows[flow_key]['subflow_fwd_packets'] += 1
        flows[flow_key]['subflow_fwd_bytes'] += length
        flows[flow_key]['fwd_iat'].append(compute_iat(flows[flow_key]['last_fwd_time'], packet.time))
        flows[flow_key]['last_fwd_time'] = packet.time
        flows[flow_key]['fin_flags'] += fin_flag
        flows[flow_key]['syn_flags'] += syn_flag
        flows[flow_key]['rst_flags'] += rst_flag
        flows[flow_key]['psh_flags'] += psh_flag
        flows[flow_key]['ack_flags'] += ack_flag
        flows[flow_key]['urg_flags'] += urg_flag
        flows[flow_key]['cwe_flags'] += cwe_flag
        flows[flow_key]['ece_flags'] += ece_flag
        flows[flow_key]['init_win_bytes_forward'] = packet[TCP].window if packet.haslayer(TCP) else 0
    elif (src_ip, src_port) == (flow_key[1], flow_key[3]):
        # Backward packet
        flows[flow_key]['total_bwd_packets'] += 1
        flows[flow_key]['total_length_bwd_packets'] += length
        flows[flow_key]['bwd_packet_lengths'].append(length)
        flows[flow_key]['bwd_header_lengths'].append(header_length)
        flows[flow_key]['subflow_bwd_packets'] += 1
        flows[flow_key]['subflow_bwd_bytes'] += length
        flows[flow_key]['bwd_iat'].append(compute_iat(flows[flow_key]['last_bwd_time'], packet.time))
        flows[flow_key]['last_bwd_time'] = packet.time
        flows[flow_key]['init_win_bytes_backward'] = packet[TCP].window if packet.haslayer(TCP) else 0

# Sniff packets
sniff(iface="Wi-Fi", prn=packet_callback, count=100)
table_data = []

# Compute final statistics
for flow_key, stats in flows.items():
    src_ip, dst_ip, src_port, dst_port, proto = flow_key
    stats['duration'] = time.time() - stats['flow_start_time']
    stats['flow_bytes_per_sec'] = (stats['total_length_fwd_packets'] + stats['total_length_bwd_packets']) / stats['duration'] if stats['duration'] > 0 else 0
    stats['flow_packets_per_sec'] = (stats['total_fwd_packets'] + stats['total_bwd_packets']) / stats['duration'] if stats['duration'] > 0 else 0

    # Forward and backward packet statistics
    if len(stats['fwd_packet_lengths']) > 1:
        stats['fwd_packet_length_max'] = max(stats['fwd_packet_lengths'])
        stats['fwd_packet_length_min'] = min(stats['fwd_packet_lengths'])
        stats['fwd_packet_length_mean'] = sum(stats['fwd_packet_lengths']) / len(stats['fwd_packet_lengths'])
        stats['fwd_packet_length_std'] = statistics.stdev(stats['fwd_packet_lengths'])
    else:
        stats['fwd_packet_length_max'] = 0
        stats['fwd_packet_length_min'] = 0
        stats['fwd_packet_length_mean'] = 0
        stats['fwd_packet_length_std'] = 0

    if len(stats['bwd_packet_lengths']) > 1:
        stats['bwd_packet_length_max'] = max(stats['bwd_packet_lengths'])
        stats['bwd_packet_length_min'] = min(stats['bwd_packet_lengths'])
        stats['bwd_packet_length_mean'] = sum(stats['bwd_packet_lengths']) / len(stats['bwd_packet_lengths'])
        stats['bwd_packet_length_std'] = statistics.stdev(stats['bwd_packet_lengths'])
    else:
        stats['bwd_packet_length_max'] = 0
        stats['bwd_packet_length_min'] = 0
        stats['bwd_packet_length_mean'] = 0
        stats['bwd_packet_length_std'] = 0

    # Flow IAT statistics
    if len(stats['fwd_iat']) > 1:
        stats['fwd_iat_mean'] = sum(stats['fwd_iat']) / len(stats['fwd_iat'])
        stats['fwd_iat_std'] = statistics.stdev(stats['fwd_iat'])
        stats['fwd_iat_max'] = max(stats['fwd_iat'])
        stats['fwd_iat_min'] = min(stats['fwd_iat'])
    else:
        stats['fwd_iat_mean'] = 0
        stats['fwd_iat_std'] = 0
        stats['fwd_iat_max'] = 0
        stats['fwd_iat_min'] = 0

    if len(stats['bwd_iat']) > 1:
        stats['bwd_iat_mean'] = sum(stats['bwd_iat']) / len(stats['bwd_iat'])
        stats['bwd_iat_std'] = statistics.stdev(stats['bwd_iat'])
        stats['bwd_iat_max'] = max(stats['bwd_iat'])
        stats['bwd_iat_min'] = min(stats['bwd_iat'])
    else:
        stats['bwd_iat_mean'] = 0
        stats['bwd_iat_std'] = 0
        stats['bwd_iat_max'] = 0
        stats['bwd_iat_min'] = 0

    # Average packet size
    total_packets = stats['total_fwd_packets'] + stats['total_bwd_packets']
    if total_packets > 0:
        stats['average_packet_size'] = (stats['total_length_fwd_packets'] + stats['total_length_bwd_packets']) / total_packets
    else:
        stats['average_packet_size'] = 0

    
    stats['avg_fwd_segment_size'] = stats['total_length_fwd_packets'] / (stats['total_fwd_packets'] if stats['total_fwd_packets'] > 0 else 1)
    stats['avg_bwd_segment_size'] = stats['total_length_bwd_packets'] / (stats['total_bwd_packets'] if stats['total_bwd_packets'] > 0 else 1)
    stats['fwd_avg_bytes_bulk'] = stats['total_length_fwd_packets'] / (stats['subflow_fwd_packets'] if stats['subflow_fwd_packets'] > 0 else 1)
    stats['fwd_avg_packets_bulk'] = stats['total_fwd_packets'] / (stats['subflow_fwd_packets'] if stats['subflow_fwd_packets'] > 0 else 1)
    stats['fwd_avg_bulk_rate'] = (stats['total_length_fwd_packets'] / stats['subflow_fwd_packets']) if stats['subflow_fwd_packets'] > 0 else 0
    stats['bwd_avg_bytes_bulk'] = stats['total_length_bwd_packets'] / (stats['subflow_bwd_packets'] if stats['subflow_bwd_packets'] > 0 else 1)
    stats['bwd_avg_packets_bulk'] = stats['total_bwd_packets'] / (stats['subflow_bwd_packets'] if stats['subflow_bwd_packets'] > 0 else 1)
    stats['bwd_avg_bulk_rate'] = (stats['total_length_bwd_packets'] / stats['subflow_bwd_packets']) if stats['subflow_bwd_packets'] > 0 else 0


    table_data.append({
        'Destination Port': dst_port,
        'Flow Duration': stats['duration'],
        'Total Fwd Packets': stats['total_fwd_packets'],
        'Total Backward Packets': stats['total_bwd_packets'],
        'Total Length of Fwd Packets': stats['total_length_fwd_packets'],
        'Total Length of Bwd Packets': stats['total_length_bwd_packets'],
        'Fwd Packet Length Max': stats['fwd_packet_length_max'],
        'Fwd Packet Length Min': stats['fwd_packet_length_min'],
        'Fwd Packet Length Mean': stats['fwd_packet_length_mean'],
        'Fwd Packet Length Std': stats['fwd_packet_length_std'],
        'Bwd Packet Length Max': stats['bwd_packet_length_max'],
        'Bwd Packet Length Min': stats['bwd_packet_length_min'],
        'Bwd Packet Length Mean': stats['bwd_packet_length_mean'],
        'Bwd Packet Length Std': stats['bwd_packet_length_std'],
        'Flow Bytes/s': stats['flow_bytes_per_sec'],
        'Flow Packets/s': stats['flow_packets_per_sec'],
        'Fwd IAT Mean': stats['fwd_iat_mean'],
        'Fwd IAT Std': stats['fwd_iat_std'],
        'Fwd IAT Max': stats['fwd_iat_max'],
        'Fwd IAT Min': stats['fwd_iat_min'],
        'Bwd IAT Mean': stats['bwd_iat_mean'],
        'Bwd IAT Std': stats['bwd_iat_std'],
        'Bwd IAT Max': stats['bwd_iat_max'],
        'Bwd IAT Min': stats['bwd_iat_min'],
        'Fwd PSH Flags': stats['fwd_flags']['PSH'],
        'Bwd PSH Flags': stats['bwd_flags']['PSH'],
        'Fwd URG Flags': stats['fwd_flags']['URG'],
        'Bwd URG Flags': stats['bwd_flags']['URG'],
        'Fwd Header Length': sum(stats['fwd_header_lengths']) / len(stats['fwd_header_lengths']) if len(stats['fwd_header_lengths']) > 0 else 0,
        'Bwd Header Length': sum(stats['bwd_header_lengths']) / len(stats['bwd_header_lengths']) if len(stats['bwd_header_lengths']) > 0 else 0,
        'Fwd Packets/s': stats['total_fwd_packets'] / stats['duration'] if stats['duration'] > 0 else 0,
        'Bwd Packets/s': stats['total_bwd_packets'] / stats['duration'] if stats['duration'] > 0 else 0,
        'Min Packet Length': min(stats['packet_lengths']),
        'Max Packet Length': max(stats['packet_lengths']),
        'Packet Length Mean': sum(stats['packet_lengths']) / len(stats['packet_lengths']) if len(stats['packet_lengths']) > 0 else 0,
        'Packet Length Std': statistics.stdev(stats['packet_lengths']) if len(stats['packet_lengths']) > 1 else 0,
        'Packet Length Variance': statistics.variance(stats['packet_lengths']) if len(stats['packet_lengths']) > 1 else 0,
        'FIN Flag Count': stats['fin_flags'],
        'SYN Flag Count': stats['syn_flags'],
        'RST Flag Count': stats['rst_flags'],
        'PSH Flag Count': stats['psh_flags'],
        'ACK Flag Count': stats['ack_flags'],
        'URG Flag Count': stats['urg_flags'],
        'CWE Flag Count': stats['cwe_flags'],
        'ECE Flag Count': stats['ece_flags'],
        'Down/Up Ratio': (stats['total_bwd_packets'] / stats['total_fwd_packets']) if stats['total_fwd_packets'] > 0 else 0,
        'Average Packet Size': stats['average_packet_size'],
        'Avg Fwd Segment Size': stats['avg_fwd_segment_size'],
        'Avg Bwd Segment Size': stats['avg_bwd_segment_size'],
        'Fwd Avg Bytes/Bulk': stats['fwd_avg_bytes_bulk'],
        'Fwd Avg Packets/Bulk': stats['fwd_avg_packets_bulk'],
        'Fwd Avg Bulk Rate': stats['fwd_avg_bulk_rate'],
        'Bwd Avg Bytes/Bulk': stats['bwd_avg_bytes_bulk'],
        'Bwd Avg Packets/Bulk': stats['bwd_avg_packets_bulk'],
        'Bwd Avg Bulk Rate': stats['bwd_avg_bulk_rate'],
        'Subflow Fwd Packets': stats['subflow_fwd_packets'],
        'Subflow Fwd Bytes': stats['subflow_fwd_bytes'],
        'Subflow Bwd Packets': stats['subflow_bwd_packets'],
        'Subflow Bwd Bytes': stats['subflow_bwd_bytes'],
        'Init_Win_bytes_forward': stats['init_win_bytes_forward'],
        'Init_Win_bytes_backward': stats['init_win_bytes_backward'],
        'act_data_pkt_fwd': stats['total_fwd_packets'] - stats['fin_flags'],
        'min_seg_size_forward': min(stats['fwd_packet_lengths']) if len(stats['fwd_packet_lengths']) > 0 else 0,
        'Active Mean': sum(stats['active_times']) / len(stats['active_times']) if len(stats['active_times']) > 0 else 0,
        'Active Std': statistics.stdev(stats['active_times']) if len(stats['active_times']) > 1 else 0,
        'Active Max': max(stats['active_times']),
        'Active Min': min(stats['active_times']),
        'Idle Mean': sum(stats['idle_times']) / len(stats['idle_times']) if len(stats['idle_times']) > 0 else 0,
        'Idle Std': statistics.stdev(stats['idle_times']) if len(stats['idle_times']) > 1 else 0,
        'Idle Max': max(stats['idle_times']),
        'Idle Min': min(stats['idle_times'])
    })

# Write to CSV
# with open('network_data_filtered_latest_last.csv', mode='w', newline='') as file:
#     writer = csv.DictWriter(file, fieldnames=table_data[0].keys())
#     writer.writeheader()
#     writer.writerows(table_data)


import csv
import os

file_path = 'network_data_filtered_latest_last.csv'


file_exists = os.path.isfile(file_path)


with open(file_path, mode='a', newline='') as file:
    writer = csv.DictWriter(file, fieldnames=table_data[0].keys())
    
   
    if not file_exists:
        writer.writeheader()
    
    writer.writerows(table_data)

