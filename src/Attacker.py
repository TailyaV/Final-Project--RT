import pyshark
import numpy as np
import os


def calculate_bitrate(packet_size, time_between):
    """
    Calculates the bitrate of network traffic.
    :return: Bitrate in Megabits per second (Mbps).
    """
    total_byte = sum(packet_size)
    total_bit = total_byte * 8  # Convert bytes to bits
    flow_time = max(time_between) - min(time_between)  # Total duration of traffic flow
    if flow_time > 0:
        return (total_bit / flow_time) / 1000000  # Convert to Mbps
    else:
        return 0


def caculate_time_arrival(pack_inter_arrival):
    """
    Computes the average inter-arrival time of packets.
    :return: Average time between packet arrivals.
    """
    time_between = []
    for i in range(len(pack_inter_arrival) - 1):
        time_between.append((pack_inter_arrival[i + 1] - pack_inter_arrival[i]))
    return np.mean(time_between)  # Compute the mean of time differences


def analyze_pcap(fileName):
    """
    Analyzes a PCAP file and extracts relevant packet information.
    :param fileName: Name of the PCAP file to analyze.
    :return: List of dictionaries containing packet details.
    """
    if not os.path.exists(fileName):
        print(f"error: file {fileName} does not exist")
        return None

    recording = pyshark.FileCapture(fileName)  # Load the PCAP file

    packet_counter = 0
    packet_size = []
    pack_inter_arrival = []
    all_packets = []

    try:
        for packet in recording:
            try:
                packet_counter += 1
                packet_info = {
                    'packet_size': int(packet.length),  # Packet size in bytes
                    'packet_time_arrival': float(packet.sniff_timestamp),  # Packet arrival time
                }
                packet_size.append(int(packet.length))
                pack_inter_arrival.append(float(packet.sniff_timestamp))
                all_packets.append(packet_info)
            except:
                pass

    except Exception as e:
        print(f"error: {e}")

    finally:
        recording.close()
        del recording

    return all_packets


def app_res(all_packets):
    """
    Processes the extracted packet data and identifies the type of traffic.
    :param all_packets: List of analyzed packets.
    """
    packet_size = [int(packet['packet_size']) for packet in all_packets]
    time_between = [packet['packet_time_arrival'] for packet in all_packets]

    avg_packet_size = np.mean(packet_size)  # Compute average packet size
    temp = np.diff(time_between)  # Compute differences in packet arrival times
    std_time_between = temp.std() * 1000  # Standard deviation of inter-arrival times in milliseconds
    bitrate = calculate_bitrate(packet_size, time_between)  # Compute bitrate

    print(f"=== summary ===")
    print(f"avg_packet_size: {round(avg_packet_size, 3)}")
    print(f"std_time_between: {round(std_time_between, 3)}")
    print(f"bitrate: {round(bitrate, 3)}")

    # Determine the type of traffic based on predefined thresholds
    if 950 < avg_packet_size < 1460 and 10 < std_time_between < 25 and 2 < bitrate < 8:
        print("The identified traffic type is: Video Streaming\n")
    elif 500 < avg_packet_size < 1200 and 5 < std_time_between < 25 and 0.5 < bitrate < 3:
        print("The identified traffic type is: Video Calls\n")
    elif 150 < avg_packet_size < 450 and 3 < std_time_between < 8 and 0.1 < bitrate < 0.3:
        print("The identified traffic type is: Audio Streaming\n")
    elif 600 < avg_packet_size < 1400 and 50 < std_time_between and 0.1 < bitrate < 5:
        print("The identified traffic type is: Internet Browsing\n")
    else:
        print("The identified traffic type is: Unknown\n")


def main():
    """
    Main function that runs the entire analysis process.
    """
    recording = [
        {"file": "chrome_browsing.pcapng", "app": "Chrome"},
        {"file": "edge_browsing.pcapng", "app": "Edge"},
        {"file": "spotify2_audio.pcapng", "app": "Spotify"},
        {"file": "youtube_video.pcapng", "app": "YouTube"},
        {"file": "zoom1_call.pcapng", "app": "Zoom"}
    ]

    all_results = []

    for rec in recording:
        print(f"analyzing {rec['app']}...")
        result = analyze_pcap(rec["file"])  # Analyze the corresponding file
        if result:
            all_results.append(result)
            app_res(result)  # Process the data and identify traffic type


if __name__ == "__main__":
    main()