# Network-Intrusion-Detection-System
Network Intrusion Detection System (NIDS)
A powerful, cross-platform Intrusion Detection System (IDS) built with Python and Scapy to monitor network traffic, detect suspicious activities, and analyze PCAP files for potential threats.
Overview
This Python-based Network Intrusion Detection System (NIDS) leverages the Scapy library to provide real-time packet capture, protocol identification, and malicious activity detection. It supports multiple modes for sniffing live traffic or analyzing PCAP files, making it suitable for network security professionals, incident responders, and researchers. The tool identifies protocols like HTTP, DNS, SMTP, SSH, SMB, and TLS/SSL, and integrates with external threat intelligence (e.g., VirusTotal API) to detect malicious behaviors such as phishing or malware.
Features

Flexible Packet Capture: Supports timed sniffing, continuous monitoring, and PCAP file analysis for versatile use cases.
Protocol Identification: Detects HTTP, DNS, SMTP, SSH, SMB, and TLS/SSL through payload and metadata analysis.
Threat Detection: Uses VirusTotal API to identify malicious domains, suspicious user agents, and SMTP misalignments.
TCP Stream Analysis: Reconstructs and analyzes network conversations for detailed inspection of raw data.
Packet Validation: Filters invalid checksums, removes duplicates, and defragments IP packets for reliable analysis.
Signature-Based Detection: Flags threats like malicious DNS queries, long cookies, or excessive HTTP POST requests.
TLS Detection: Employs entropy analysis to identify encrypted TLS/SSL sessions.
Output Flexibility: Saves packets as PCAP and logs as text in a configurable directory.
Cross-Platform Support: Compatible with Windows, Linux, and macOS.
Interactive Analysis: Lists streams with IP/port details and supports interactive DNS data inspection.

Installation
Prerequisites

Python 3.8+
Scapy (pip install scapy)
Additional dependencies: numpy, requests (pip install numpy requests)

Setup

Clone the repository:git clone https://github.com/yourusername/nids.git
cd nids


Install dependencies:pip install -r requirements.txt


(Optional) Configure a VirusTotal API key for malicious activity detection by setting it as an environment variable or in a configuration file.

Usage
Run the tool using the command-line interface with the following modes:
Mode 1: Sniff for Seconds
Capture packets for a specified duration and save results.
python nids.py -m 1 -i <interface> -t <seconds> -s <filename> -o <output_dir>

Example:
python nids.py -m 1 -i eth0 -t 60 -s capture -o ./output

Mode 2: Sniff Forever
Continuously monitor network traffic until manually stopped.
python nids.py -m 2 -i <interface>

Example:
python nids.py -m 2 -i eth0

Mode 3: Analyze PCAP File
Analyze a PCAP file and investigate specific streams.
python nids.py -m 3 -p <pcap_file> --stream <stream_number> -o <output_dir>

Example:
python nids.py -m 3 -p capture.pcap --stream 1 -o ./output

Repository Structure
nids/
├── nids.py               # Main IDS script
├── requirements.txt      # Python dependencies
├── README.md             # This file
├── LICENSE               # License file (MIT)
└── output/               # Default output directory for logs and PCAPs

Example Output
When analyzing a PCAP file in Mode 3:
Total Streams Found: 5
Stream 1: 192.168.1.1:1234 → 192.168.1.2:80 (Packets: 10)
Stream 2: 192.168.1.3:5678 → 8.8.8.8:53 (Packets: 3)
...
Enter the Stream Number You Want To Follow: 1
Your Stream Raw Data Has Been Written To The Default Directory
Identifying Protocol
The Identified Protocol is: HTTP
############# Domain Reputation Is Categorized As Malicious. #############

Contributing
Contributions are welcome! To contribute:

Fork the repository.
Create a new branch (git checkout -b feature/your-feature).
Commit your changes (git commit -m "Add your feature").
Push to the branch (git push origin feature/your-feature).
Open a pull request.

Please ensure your code adheres to the project's coding standards and includes relevant tests.
License
This project is licensed under the MIT License. See the LICENSE file for details.
Acknowledgments

Built with Scapy for packet manipulation.
Uses VirusTotal API for threat intelligence.
Inspired by open-source cybersecurity tools and community feedback.

Contact
For questions, suggestions, or collaboration, please open an issue or reach out via GitHub.
