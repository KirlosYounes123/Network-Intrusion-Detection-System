# Network Intrusion Detection System (NIDS)

A robust, cross-platform Intrusion Detection System (IDS) developed in Python using the Scapy library. This tool empowers network security professionals to monitor live traffic, analyze packet captures (PCAPs), and detect potential threats with precision. It combines real-time packet sniffing, protocol identification, and malicious activity detection to provide actionable insights for securing networks.

## Overview

The Network Intrusion Detection System (NIDS) is designed to enhance network security by capturing and analyzing network packets in real-time or from stored PCAP files. Leveraging Scapy's powerful packet manipulation capabilities, it identifies protocols such as HTTP, DNS, SMTP, SSH, SMB, and TLS/SSL, and integrates with external threat intelligence services like VirusTotal to detect malicious behaviors, including phishing, malware, and suspicious network patterns. The tool is suitable for network administrators, incident responders, security analysts, and researchers seeking to monitor, analyze, and protect network environments.

## Features

- **Multiple Capture Modes**: Offers three operational modes to suit diverse needs:
  - **Timed Sniffing**: Captures packets for a user-specified duration, ideal for short-term monitoring or testing.
  - **Continuous Sniffing**: Runs indefinitely for ongoing network surveillance until manually stopped.
  - **PCAP Analysis**: Processes stored PCAP files to reconstruct and analyze network sessions for forensic investigations.
- **Advanced Protocol Identification**: Accurately detects and classifies protocols (HTTP, DNS, SMTP, SSH, SMB, TLS/SSL) by analyzing packet payloads, headers, and metadata, enabling detailed traffic profiling.
- **Malicious Activity Detection**: Integrates with the VirusTotal API to check for malicious domains, suspicious user agents, SMTP header misalignments, and other indicators of compromise, such as recently registered domains or excessive HTTP POST requests.
- **TCP Stream Reconstruction**: Reassembles TCP streams to reconstruct complete network conversations, extracting raw data for in-depth analysis of communication flows.
- **Packet Validation and Preprocessing**: Ensures data integrity by:
  - Filtering packets with invalid checksums.
  - Removing duplicate TCP packets based on sequence numbers.
  - Defragmenting IP packets to handle fragmented traffic accurately.
- **Signature-Based Threat Detection**: Employs custom signatures to identify specific threats, such as:
  - DNS queries to malicious top-level domains.
  - Overly long HTTP cookies potentially containing encoded malicious data.
  - Excessive HTTP POST requests indicative of brute-force or data exfiltration attempts.
  - SMTP header misalignments suggesting phishing attempts.
- **TLS/SSL Detection**: Uses entropy analysis to identify encrypted TLS/SSL sessions, even when traditional protocol markers are absent, ensuring visibility into encrypted traffic.
- **Flexible Output Options**: Saves captured packets in PCAP format and detailed logs (e.g., protocol summaries, raw data) in text format to a user-configurable directory, facilitating integration with other tools and workflows.
- **Cross-Platform Compatibility**: Operates seamlessly on Windows, Linux, and macOS, making it accessible across diverse environments.
- **Interactive Stream Analysis**: Lists all detected streams with details like source/destination IPs, ports, and packet counts, allowing users to select specific streams for deeper investigation.
- **DNS Data Extraction**: Extracts and saves DNS query details to a dedicated file, with an option to display packet contents interactively for rapid analysis of DNS-based threats.
- **Customizable Logging**: Generates detailed logs for alarms (e.g., malicious domain detections) with timestamps, alarm codes, and context, stored in a designated output directory.
- **Error Handling and Robustness**: Includes comprehensive error handling for malformed packets, invalid inputs, and API failures to ensure reliable operation under various conditions.

## Installation

### Prerequisites
- **Python**: Version 3.8 or higher.
- **Scapy**: For packet manipulation and analysis (`pip install scapy`).
- **Additional Libraries**: `numpy` for entropy calculations and `requests` for API interactions (`pip install numpy requests`).
- **VirusTotal API Key**: Optional, for malicious activity detection (sign up at [VirusTotal](https://www.virustotal.com/) to obtain a key).
- **Network Interface**: A compatible network interface for live packet capture (e.g., `eth0` on Linux, `Ethernet` on Windows).

### Setup Instructions
1. Clone the repository:
   ```bash
   git clone https://github.com/KirlosYounes123/nids.git
   cd nids
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. (Optional) Configure the VirusTotal API key:
   - Set it as an environment variable: `export VT_API_KEY=your_api_key`
   - Alternatively, modify the script to include the API key directly (not recommended for security reasons).
4. Ensure the `output/` directory exists or specify a custom output directory using the `--output` argument.

## Usage

The tool is operated via a command-line interface with three modes, specified using the `--mode` or `-m` argument. Below are the details for each mode.

### Mode 1: Sniff for Seconds
Captures packets for a specified duration and saves results to files.
```bash
python nids.py -m 1 -i <interface> -t <seconds> -s <filename> -o <output_dir>
```
- `-i <interface>`: Network interface name (e.g., `eth0`, `Wi-Fi`).
- `-t <seconds>`: Duration to capture packets (in seconds).
- `-s <filename>`: Base filename for saved PCAP and text logs.
- `-o <output_dir>`: Output directory (default: `./output`).
Example:
```bash
python nids.py -m 1 -i eth0 -t 60 -s capture -o ./output
```

### Mode 2: Sniff Forever
Continuously monitors network traffic until manually stopped (Ctrl+C).
```bash
python nids.py -m 2 -i <interface>
```
Example:
```bash
python nids.py -m 2 -i eth0
```

### Mode 3: Analyze PCAP File
Analyzes a PCAP file to identify streams, extract data, and detect threats.
```bash
python nids.py -m 3 -p <pcap_file> --stream <stream_number> -o <output_dir>
```
- `-p <pcap_file>`: Path to the PCAP file.
- `--stream <stream_number>`: Specific stream to analyze (optional; prompts for input if omitted).
- `-o <output_dir>`: Output directory (default: `./output`).
Example:
```bash
python nids.py -m 3 -p capture.pcap --stream 1 -o ./output
```

## Repository Structure

```
nids/
├── nids.py               # Main IDS script containing all functionality
├── requirements.txt      # List of Python dependencies
├── README.md             # This documentation file
├── LICENSE               # MIT License file
└── output/               # Default directory for logs and PCAP files
```

## Example Output

When running Mode 3 to analyze a PCAP file:
```
Total Streams Found: 5
Stream 1: 192.168.1.1:1234 → 192.168.1.2:80 (Packets: 10)
Stream 2: 192.168.1.3:5678 → 8.8.8.8:53 (Packets: 3)
Stream 3: 10.0.0.1:443 → 10.0.0.2:56789 (Packets: 15)
Stream 4: 192.168.1.4:25 → 192.168.1.5:12345 (Packets: 8)
Stream 5: Non-TCP or malformed stream
Enter the Stream Number You Want To Follow: 1
Your Stream Raw Data Has Been Written To The Default Directory
Identifying Protocol
The Identified Protocol is: HTTP
############# Domain Reputation Is Categorized As Malicious. #############
A HTTP Request For A Malicious Domain Was Done On 2025-08-03 08:03:45
Alarm Code: HTTP01
Name: Reputation
Domain: examplemalicious.com
```

## Configuration

- **Output Directory**: By default, logs and PCAPs are saved to the `./output` directory. Use the `--output` flag to specify a custom path.
- **VirusTotal API**: Replace the placeholder API key in `nids.py` with your own, or set it as an environment variable for secure usage.
- **Bad User Agents**: The tool references a `bad-user-agents.list` file for HTTP user-agent checks. Create this file in the output directory or update the path in the script.

## Contributing

Contributions are encouraged to enhance the tool's functionality, performance, or usability. To contribute:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit your changes with clear messages (`git commit -m "Add your feature"`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a pull request with a detailed description of your changes.

Please adhere to the following guidelines:
- Follow Python PEP 8 style conventions.
- Include comments for complex logic.
- Test changes thoroughly, especially for packet processing and API interactions.

## Troubleshooting

- **Permission Issues**: Ensure you have sufficient permissions to capture packets (e.g., run as root on Linux with `sudo`).
- **Interface Not Found**: Verify the interface name using `ifconfig` (Linux) or `ipconfig` (Windows).
- **API Errors**: Check your VirusTotal API key and network connectivity if threat detection fails.
- **Malformed Packets**: The tool automatically filters invalid packets, but ensure PCAP files are not corrupted.

## Acknowledgments

- **Scapy**: For providing a robust framework for packet manipulation and analysis.
- **VirusTotal**: For enabling threat intelligence integration via their API.
- **Open-Source Community**: For inspiring and supporting the development of cybersecurity tools.

## Contact

For questions, bug reports, or collaboration opportunities, please:
- Open an issue on GitHub.
- Reach out via email or LinkedIn (update with your contact details).
- Join the discussion in the repository's Issues or Discussions sections.
