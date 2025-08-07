# Tunnelbreach - SSH Honeypot

## Overview

Tunnelbreach is a Python-based SSH honeypot designed to simulate a vulnerable SSH server. This tool has been developed for research and educational purposes in the field of cybersecurity within academic environments, allowing researchers to study and analyze intrusion techniques.

## Features

- **SSH Server Simulation**: Provides responses similar to real SSH servers
- **Connection Logging**: Documents all connection attempts and transmitted data
- **Automatic Log Rotation**: Manages log files with a rotation system
- **Real-time Statistics**: Displays activity statistics and attacker IPs
- **Concurrent Connection Management**: Controls the number of simultaneous connections
- **Customizable Responses**: Randomized SSH banners and authentication failure messages
- **Thread Pool Management**: Efficient handling of multiple connection attempts

## Installation

Clone the repository (if using version control)

```bash
git clone https://github.com/naseridev/tunnelbreach.git
cd tunnelbreach
```

Make the script executable

```bash
chmod +x tunnelbreach.py
```

## Usage

Tunnelbreach can be run with various command-line options to customize its behavior:

```bash
./tunnelbreach.py run [OPTIONS]
```

### Command-line Options

| Option | Description |
|--------|-------------|
| `-p, --port PORT` | Port number to listen on (default: 22) |
| `-s, --stealth` | Run in stealth mode with minimal output |
| `-w, --workers WORKERS` | Maximum number of worker threads (default: 20) |
| `-c, --connections CONNECTIONS` | Maximum number of concurrent connections (default: 100) |

### Examples

Run with default settings (requires root privileges for port 22):
```bash
sudo ./tunnelbreach.py run
```

Run on a non-privileged port:
```bash
./tunnelbreach.py run -p 2222
```

Run in stealth mode with increased capacity:
```bash
./tunnelbreach.py run -s -w 50 -c 200
```

## Log Files

Log files are stored in the `_logs` directory with the following naming convention:
```
honeypot_YYYYMMDD_HHMMSS.log
```

The logs contain detailed information about connection attempts, including:
- IP addresses and ports
- Timestamp of connection
- Data transmitted by attackers
- System status and errors

## Security Considerations

- **Always run honeypots in a controlled, isolated environment**
- **Never deploy on production systems**
- **Regular monitoring is recommended to prevent abuse**
- **Review logs frequently for potential security insights**

## Academic Usage

This tool is particularly suitable for:
- Cybersecurity courses and labs
- Network security research
- Threat intelligence gathering
- Behavioral analysis of SSH-targeting attacks

## Requirements

- Python 3.6 or higher
- Privileged access (if using port numbers below 1024)
- Compatible with Linux, macOS, and Windows

## Disclaimer

This software is provided for educational and research purposes only. The authors are not responsible for any misuse or damage caused by this program. Always ensure you have proper authorization before deploying honeypots on any network.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
