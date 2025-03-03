import pyshark
import matplotlib.pyplot as plt
import numpy as np
import os

"""
function that receive array of capture times of all packets and calculate the average of the time between every tow packets  
"""
def caculate_time_arrival(pack_inter_arrival):
    time_between = []
    for i in range(len(pack_inter_arrival) - 1):
        time_between.append((pack_inter_arrival[i + 1] - pack_inter_arrival[i])*1000)
    return np.mean(time_between)
"""
Function that receives the recording path and the app name, then calculates:
- The percentage of packets with TCP, QUIC, IP, and TLS headers
- The total number of packets in the recording
- The average packet size
- The average time between every two consecutive packets by passing all packets.
"""

def analyze_pcap(fileName, appName):
    if not os.path.exists(fileName):
        print(f"error: file {fileName} does not exist")
        return None
    recording = pyshark.FileCapture(fileName)

    ip_header = 0
    tcp_header = 0
    tls_header = 0
    quic_header = 0
    packet_counter = 0
    packet_size = []
    pack_inter_arrival = []
    tls_strings = {}

    try:
        for packet in recording:
            try:
                packet_counter += 1
                packet_size.append(int(packet.length))
                pack_inter_arrival.append(float(packet.sniff_timestamp))

                if 'IP' in packet:
                    ip_header = ip_header + 1
                if 'TCP' in packet:
                    tcp_header = tcp_header + 1
                if 'TLS' in packet:
                    if 'tls' in packet.frame_info.protocols:
                        tls_header = tls_header + 1
                if 'QUIC' in packet:
                    quic_header = quic_header + 1
            except:
                pass

    except Exception as e:
        print(f"error: {e}")

    finally:
        recording.close()
        del recording

    avg_packet_size = np.mean(packet_size)
    avg_inter_arrival_time = caculate_time_arrival(pack_inter_arrival)
    if packet_counter > 0:
        tcp_per = tcp_header/packet_counter*100
    else:
        tcp_per = 0.0
    if packet_counter > 0:
        tls_per = tls_header/packet_counter*100
    else:
        tls_per = 0.0
    if packet_counter > 0:
        quic_per = quic_header/packet_counter*100
    else:
        quic_per = 0.0
    flow_volume = sum(packet_size)

    result = {
        "appName": appName,
        "packet_number": packet_counter,
        "ip_header": ip_header,
        "tcp_header": tcp_header,
        "tls_header": tls_header,
        "quic_header": quic_header,
        "avg_packet_size": avg_packet_size,
        "avg_inter_arrival_time": avg_inter_arrival_time,
        "tcp_per": tcp_per,
        "tls_avg":tls_per,
        "quic_avg":quic_per,
        "flow_volume": flow_volume/(1024*1024),
        "flow_size": packet_counter,
    }
    return result

"""
Function to create and save multiple graphs comparing various network traffic characteristics for each app. 
It generates graphs for:
- Average packet size
- Average inter-arrival time
- Percentage of TCP, TLS, QUIC packets
- Flow volume and flow size
"""

def creat_graph(results):
    if not results:
        print("no results")
        return None
    appName = []
    avg_packet_size = []
    avg_inter_arrival_time = []
    tcp_precent = []
    tls_precent = []
    quic_precent = []
    flow_volume = []
    flow_size = []
    colors = ['#FFB6C1', '#FF69B4', '#FF1493', '#C71585', '#DB7093']

    for res in results:
        appName.append(res["appName"])
        avg_packet_size.append(res["avg_packet_size"])
        avg_inter_arrival_time.append(res["avg_inter_arrival_time"])
        tcp_precent.append(res["tcp_per"])
        tls_precent.append(res["tls_avg"])
        quic_precent.append(res["quic_avg"])
        flow_volume.append(res["flow_volume"])
        flow_size.append(res["flow_size"])

    plt.figure(figsize = (10,6))
    plt.bar(appName, avg_packet_size, color = colors)
    plt.title("Average packet size")
    plt.ylabel("Bytes")
    plt.xlabel("Application")
    plt.savefig("packet_size.png")
    plt.close()
    print(f"created packet size avg comparison graph")

    plt.figure(figsize=(10, 6))
    plt.bar(appName, avg_inter_arrival_time, color = colors)
    plt.title("Average inter arrival time(ms)")
    plt.ylabel("Milliseconds")
    plt.xlabel("Application")
    plt.savefig("inter_arrival_time.png")
    plt.close()
    print(f"created avg arrival time comparison graph")

    plt.figure(figsize=(10, 6))
    plt.bar(appName, tcp_precent, color = colors)
    plt.title("percent tcp packets headers")
    plt.ylabel("Percentage")
    plt.ylim(0,100)
    for i, v in enumerate(tcp_precent):
        plt.text(i, v + 1, f"{v:.1f}%", ha="center")
    plt.tight_layout()
    plt.xlabel("Application")
    plt.savefig("tcp_packets_header.png")
    plt.close()
    print(f"created tcp headers percent comparison graph")

    plt.figure(figsize=(10, 6))
    plt.bar(appName, tls_precent, color = colors)
    plt.title("percent tls packets headers")
    plt.ylabel("Percentage")
    plt.ylim(0, 100)
    for i, v in enumerate(tls_precent):
        plt.text(i, v + 1, f"{v:.1f}%", ha="center")
    plt.tight_layout()
    plt.xlabel("Application")
    plt.savefig("tls_packets_header.png")
    plt.close()
    print(f"created tls headers percent comparison graph")

    plt.figure(figsize=(10, 6))
    plt.bar(appName, quic_precent, color = colors)
    plt.title("percent quic packets headers")
    plt.ylabel("Percentage")
    plt.ylim(0, 100)
    for i, v in enumerate(quic_precent):
        plt.text(i, v + 1, f"{v:.1f}%", ha="center")
    plt.tight_layout()
    plt.xlabel("Application")
    plt.savefig("quic_packets_header.png")
    plt.close()
    print(f"created quic headers percent comparison graph")

    plt.figure(figsize=(10, 6))
    plt.bar(appName, flow_volume, color=colors)
    plt.title("Flow volume")
    plt.ylabel("Megabytes")
    plt.xlabel("Application")
    plt.savefig("flow_volume.png")
    plt.close()
    print(f"created flow volume comparison graph")

    plt.figure(figsize=(10, 6))
    plt.bar(appName, flow_size, color=colors)
    plt.title("Flow size")
    plt.ylabel("Packets")
    plt.xlabel("Application")
    plt.savefig("flow_size.png")
    plt.close()
    print(f"created flow size comparison graph")

"""
Main function that processes a list of pcap file paths with application names,
analyzes the data, and generates graphs comparing network traffic characteristics 
of different applications.
"""

def main():
    recording = [
        {"file": "chrome_browsing.pcapng", "app": "Chrome"},
        {"file": "edge_browsing.pcapng", "app": "Edge"},
        {"file": "spotify2_audio.pcapng", "app": "Spotify"},
        {"file": "youtube_video.pcapng", "app": "YouTube"},
        {"file": "zoom1_call.pcapng", "app": "Zoom"}
    ]

    all_results =[]

    for rec in recording:
        print(f"analyzing {rec['app']}...")
        result = analyze_pcap(rec["file"], rec["app"])
        if result:
            all_results.append(result)

            print(f"==={rec['app']} summary===")
            print(f"packet count: {result['packet_number']}")
            print(f"ip header: {result['ip_header']}")
            print(f"tcp header: {result['tcp_header']}")
            print(f"tls header: {result['tls_header']}")
            print(f"quic header: {result['quic_header']}")
            print(f"avg packet size: {round(result['avg_packet_size'], 3)}")
            print(f"avg inter arrival time: {round(result['avg_inter_arrival_time'], 5)}")
            print(f"flow volume(MB): {round(result['flow_volume'], 3)}")
            print(f"flow size: {result['flow_size']}\n")
    if len(all_results) > 0:
        if len(all_results) > 1:
            creat_graph(all_results)
        else:
            print("no comparison results")
    else:
        print(f"no results")



if __name__ == "__main__":
    main()



