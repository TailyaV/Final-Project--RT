# Final-Project--RT


##README FILE- Attacker

This project analyzes network traffic from PCAP files and identifies the type of network activity based on packet size, inter-arrival time, and bitrate. The program categorizes traffic into types such as Video Streaming, Video Calls, Audio Streaming, and Internet Browsing.
The program does:
-Extracts packet size and arrival time
-Calculates network traffic details like bitrate and standard deviation of packet inter-arrival times
-Identifies network traffic types based on predefined thresholds

## Requirements
Python version-
- Python 3.13
To run this project, you'll need to install the following libraries:
- pyshark library for packet capture analysis (Install with -pip install pyshark)
- os library for file path (a built-in Python module)
- numpy package for numerical calculations (Install with -pip install numpy)
-must attach the PCAP recordinig to the project folder and wright the files name in "main" function where wrighten "file:".

## Output
Output summarizing key statistics and type for each recording, 
-Average packet size
-Std of time between every to follow packets
-bitrate- amount of bit for second
-Type of recording

## Functions
-Function that calculates the bitrate of network traffic in Megabits per second.
-Function that computes the average time between packet arrivals.
-Function that loads a PCAP file and extracts packet size and timestamp information.
-Function that processes extracted packet data and determines the type of network activity.


##README FILE- Graphs

This project analyze traffic from Wireshark PCAP files to compare different app traffic characteristics.
It processes packet capture files to generate statistical information and visual comparisons of network behavior of ZOOM, Spotify, YouTube, Edge, Chrome.

The program does-
- Analyzes packet capture files for multiple applications
- Calculates packet metrics including:
  - Average packet size
  - Average inter-arrival time between packets
  - Percentage of TCP, TLS, and QUIC packet headers
  - Total flow volume and flow size
- Generates comparative graphs for visual analysis
- Outputs detailed summary statistics for each application

## Requirements
Python version-
- Python 3.13
To run this project, you'll need to install the following libraries:
- pyshark library for packet capture analysis (Install with -pip install pyshark)
- os library for file path (a built-in Python module)
- numpy package for numerical calculations (Install with -pip install numpy)
- matplotlib library for graph generation (Install with -pip install matplotlib)
-must attach the PCAP recordinig to the project folder and wright the files name in "main" function where wrighten "file:"

## Output
The tool generates:
1. Console output summarizing key statistics for each application
2. Seven comparison graphs saved as PNG files:
   - packet_size.png: Average packet size comparison
   - inter_arrival_time.png: Average packet inter-arrival time comparison
   - tcp_packets_header.png: TCP header percentage comparison
   - tls_packets_header.png: TLS header percentage comparison
   - quic_packets_header.png: QUIC header percentage comparison
   - flow_volume.png: Total flow volume comparison
   - flow_size.png: Total packet count comparison

## Functions
- analyze_pcap(fileName, appName): Analyzes a single packet capture file
- caculate_time_arrival(pack_inter_arrival): Calculates average inter-arrival time
- creat_graph(results): Generates comparative graphs based on analysis results
- main(): Main function that processes files and runs the analysis
