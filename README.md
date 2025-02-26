# TunnelBreach SSH Honeypot

TunnelBreach is a lightweight, configurable SSH honeypot designed to detect, monitor, and log unauthorized SSH connection attempts. By simulating a vulnerable SSH server, it helps security researchers and system administrators understand attack patterns and monitor potential threats.

## Features

- **Easy Deployment:** Simple setup with minimal configuration required
- **Customizable SSH Banners:** Randomly selects from common SSH server banners to appear authentic
- **Detailed Logging:** Records all connection attempts with timestamps, IP addresses, and attempted credentials
- **Real-time Monitoring:** Shows connection attempts as they happen with color-coded terminal output
- **Statistical Analysis:** Tracks top attackers and provides summary statistics
- **Stealth Mode:** Option to run with minimal console output for quiet operation

## Requirements

- Python 3.6 or higher
- Standard Python libraries (all included in the script)

## Installation

Clone the repository:

```bash
git clone https://github.com/naseridev/TunnelBreach
cd TunnelBreach
```

No additional installation steps are required as the script uses only standard Python libraries.

## Usage

### Basic Usage

Run the honeypot on the default SSH port (22):

```bash
sudo python3 Tunnelbreach.py run
```

*Note: Running on ports below 1024 (like the default port 22) requires root/administrator privileges.*

### Custom Port

Run the honeypot on a custom port:

```bash
python3 Tunnelbreach.py run 2222
```

### Stealth Mode

Run with minimal console output:

```bash
python3 Tunnelbreach.py run --stealth
```

Or with a custom port:

```bash
python3 Tunnelbreach.py run 2222 --stealth
```

## Log Files

All connection attempts are logged to the `_logs` directory in the format `honeypot_YYYYMMDD_HHMMSS.log`. These logs contain:

- Timestamp of connection
- Source IP and port
- Any data sent by the attacker
- Number of connection attempts from each IP

## How It Works

TunnelBreach works by:

1. Opening a socket on the specified port
2. Sending a realistic SSH banner when a connection is received
3. Logging connection details and any received data
4. Responding with plausible "access denied" messages
5. Keeping statistics on connection attempts

## Security Considerations

- This tool is intended for research and educational purposes only
- Always deploy honeypots in controlled environments
- Consider legal and ethical implications before deployment
- Do not use on production servers without proper isolation

## Customization

You can modify the SSH banners and responses by editing the `SSH_BANNERS` and `SSH_RESPONSES` lists in the script.

## Disclaimer

This tool is for educational and research purposes only. The developers assume no liability and are not responsible for any misuse or damage caused by this program.

## Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/naseridev/TunnelBreach/issues).
