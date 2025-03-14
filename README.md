# Cybersecurity Intrusion Detection System (IDS)

## Overview
This Intrusion Detection System (IDS) is a network security tool written in C++ using `libpcap`. It monitors network traffic, detects abnormal activity, and raises alerts for potential intrusions.

## Features
- Captures live network traffic.
- Monitors packet frequency for each IP.
- Detects potential intrusions based on activity thresholds.
- Highlights alerts in red for better visibility.
- Provides real-time logging of network activity.

## Installation
### Prerequisites
- **Linux-based OS (Ubuntu, Kali, etc.)**
- **`libpcap` library installed**
  ```sh
  sudo apt-get install libpcap-dev
  ```
- **C++ Compiler (g++)**
  ```sh
  sudo apt install g++
  ```

## Compilation & Execution
1. **Compile the Program:**
   ```sh
   g++ intrusion_detection.cpp -o intrusion_detection -lpcap
   ```
2. **Run with Sudo:**
   ```sh
   sudo ./intrusion_detection
   ```
3. **Select the Network Interface:**
   - The program lists available interfaces.
   - Enter the number of the interface to monitor.

## How It Works
- The program continuously captures packets from the chosen interface.
- It tracks the frequency of packets from each IP address.
- If an IP exceeds a threshold within a short time window, it triggers an alert.
- Alerts appear in red for better visibility.

## Notes
- Requires **root privileges** to capture network traffic.
- Works best in a **LAN/Wi-Fi network** environment.
- Can be extended to detect port scans, DoS attacks, etc.
