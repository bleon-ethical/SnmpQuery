# SnmpQuery - Network Discovery and Monitoring Tool

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)

**SnmpQuery** is an open-source network monitoring and discovery solution designed for small to medium-sized businesses that need professional-grade network visibility without enterprise-level costs. Built with Python, it leverages SNMP, NetFlow, and ARP table analysis to provide real-time insights into network topology, device connectivity, and traffic patterns.

## Why SnmpQuery?

Many small and medium businesses struggle with limited budgets for network monitoring tools. SnmpQuery bridges this gap by providing:

- 🔍 **Real-time device monitoring** through SNMP and ARP table analysis
- 🌐 **Network topology mapping** with automatic switch hierarchy detection
- 📊 **Optional NetFlow traffic analysis** for bandwidth monitoring
- 🖥️ **Web-based dashboard** for easy management and queries
- 💰 **Zero licensing costs** - completely free and open source
- 🛠️ **Built for reality** - tested in production with Cisco ISR routers and budget L2 managed switches

Perfect for IT staff at small businesses, MSPs managing multiple sites, or anyone who needs visibility into their network without breaking the budget.


## Quick Start

**Want to try it quickly? Minimal setup:**
```bash
# 1. Install and configure
sudo apt install -y snmp nbtscan
git clone https://github.com/agmaiztegui/SnmpQuery.git
cd SnmpQuery
pip3 install -r requirements.txt
cp snmpQuery.ini.example snmpQuery.ini
nano snmpQuery.ini  # Add your switches and network

# 2. Create ramdisk
sudo mkdir -p /ramdisk
sudo mount -t tmpfs -o size=512M tmpfs /ramdisk
sudo chmod 1777 /ramdisk

# 3. Start monitoring daemon
touch snmpPyServer.running
python3 snmpPyServer.py &

# 4. Start web interface (in new terminal)
export FLASK_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
python3 flask_web_server.py
```

**Then open:** `http://localhost:5000`

💡 **For production deployment with systemd services, see [Usage](#usage) section**

## Features

### Core Monitoring
- **MAC address tracking**: Real-time MAC-to-port mapping across all switches
- **Hostname resolution**: NetBIOS (reverse DNS lookups in future releases)
- **Switch topology mapping**: Automatic detection of switch hierarchy (how switches interconnect)
- **Port classification**: Automatic identification of trunk ports, access ports, and gateway ports

### NetFlow Analysis (Optional)
- **Traffic flow collection**: Collects NetFlow v9 data from network devices
- **Directional analysis**: Separates upstream/downstream traffic
- **Public/Private classification**: Distinguishes internet vs internal traffic
- **Well Known Service identification**: Recognizes traffic to major services (Google, AWS, Netflix, etc.)
- **Per-host statistics**: View bandwidth usage by device

### Web Interface
- **Dashboard**: Real-time overview of all network devices
- **Query system**: Search by IP address, MAC address, or switch port
- **NetFlow visualization**: View bandwidth statistics and top talkers
- **Auto-refresh**: Live updates for monitoring changing conditions

## Screenshot Preview


![Alt text](/screenshots/01_dash1.png?raw=true "Dashboard top")

![Alt text](/screenshots/02_dash2.png?raw=true "Dashboard bottom")

![Alt text](/screenshots/03_report.png?raw=true "Switch Report")

![Alt text](/screenshots/04_ipaddress.png?raw=true "IP Address Search")

![Alt text](/screenshots/05_switchport.png?raw=true "Switchport List")

![Alt text](/screenshots/06_map.png?raw=true "Switch Mapping")

![Alt text](/screenshots/07_vendors.png?raw=true "MAC Address Vendor Detail")


## System Requirements

### Software Dependencies

**Python Libraries:**
- Flask >= 2.0 (BSD-3-Clause)
- Flask-Login >= 0.6 (MIT)
- prompt_toolkit >= 3.0 (BSD-3-Clause)

**System Tools (must be installed):**
- `net-snmp` tools (`snmpbulkwalk`, `snmpget`)
- `nbtscan` (recommended, for NetBIOS hostname resolution)
- `nfacctd` from pmacct (optional, for NetFlow collection)

### Hardware Requirements
- **RAM**: Minimum 512MB, 1GB+ recommended for NetFlow
- **Storage**: 10GB+ (uses `/ramdisk/` for high-performance database operations)
- **Network Access**: SNMP read access to network devices

### Tested Environments
- ✅ Debian 13+, Kali 2022
- ✅ Cisco ISR routers (tested: ISR 4000, 2800 and 1900 series)
- ✅ L2 managed switches with SNMP support
- ⚠️ Other network hardware may work but has not been extensively tested

## Installation

### 1. Install System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install -y snmp nbtscan
```

**For NetFlow support (optional):**
```bash
sudo apt install -y pmacct
```

### 2. Clone Repository
```bash
git clone https://github.com/agmaiztegui/SnmpQuery.git
cd snmpquery
```

### 3. Install Python Dependencies
```bash
pip3 install -r requirements.txt
```

### 4. Create RAMDisk
create a ramdisk for database operations:
```bash
sudo mkdir -p /ramdisk
sudo mount -t tmpfs -o size=512M tmpfs /ramdisk
sudo chmod 1777 /ramdisk
```

To make it permanent, add to `/etc/fstab`:
```
tmpfs  /ramdisk  tmpfs  defaults,size=512M  0  0
```

### 5. Configure Your Network

Create your configuration file from the example:
```bash
cp snmpQuery.ini.example snmpQuery.ini
```

Edit `snmpQuery.ini` with your network details:
```ini
# Network Settings
NETWORK=192.168.1.0
MASKBITS=24
gateway=192.168.1.1
community=public

# START_SWITCHES
# List your switches here (IP=Description)
192.168.1.10=Core Switch
192.168.1.11=Distribution Switch 1
# END_SWITCHES

# Access Points (Optional)
AP=aa:bb:cc:dd:ee:ff=Main Office AP
```

### 6. Enable the Service
Create the operation flag file:
```bash
touch snmpPyServer.running
```

## Usage

### Starting the Core Service
```bash
python3 snmpPyServer.py
```

This daemon will:
- Query all configured switches via SNMP
- Update MAC address tables
- Maintain device database
- Track network topology

### Starting NetFlow Collection (Optional)
Terminal 1 - NetFlow Collector:
```bash
python3 nfacctd-collector.py
```

Terminal 2 - NetFlow Processor:
```bash
python3 netflowProcessor.py
```

### Starting the Web Interface

**1. Generate a secure secret key:**
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

**2. Set the environment variable:**

Choose one method:

**Option A - Temporary (for testing):**
```bash
export FLASK_SECRET_KEY="paste-your-generated-key-here"
python3 flask_web_server.py
```

**Option B - Permanent (add to .bashrc):**
```bash
echo 'export FLASK_SECRET_KEY="paste-your-generated-key-here"' >> ~/.bashrc
source ~/.bashrc
python3 flask_web_server.py
```

**Option C - Using .env file (recommended):**
```bash
# Create .env file in project directory
echo 'FLASK_SECRET_KEY="paste-your-generated-key-here"' > .env

# Install python-dotenv
pip3 install python-dotenv

# Run the server
python3 flask_web_server.py
```

**3. Access the interface:**
Open your browser to: `http://localhost:5000`

**Default credentials** (change immediately in production!):
- Username: `admin` or `operator`
- Password: Configured in `flask_web_server.py` (see USERS dictionary)

> **Security Note:** The Flask app will generate a random session key automatically if `FLASK_SECRET_KEY` is not set, but sessions won't persist across restarts. For production use, always set a permanent key.
### Query Examples

**Find device by IP:**
```
http://localhost:5000/query?q=192.168.1.100
```

**Find device by MAC:**
```
http://localhost:5000/query?q=aa:bb:cc:dd:ee:ff
```

**View switch port details:**
```
http://localhost:5000/query?q=switchport+192.168.1.10+12
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Network Devices                      │
│  (Cisco Routers, Switches, APs, Endpoints)              │
└────────┬──────────────────────────────────┬─────────────┘
         │ SNMP                             │ NetFlow v9
         │ (UDP 161)                        │ (UDP 2055)
         ▼                                  ▼
┌────────────────────┐            ┌──────────────────────┐
│  snmpPyServer.py   │            │ nfacctd-collector.py │
│  (Core Daemon)     │            │  (NetFlow Daemon)    │
│                    │            │                      │
│  - SNMP queries    │            │  - Receives flows    │
│  - ARP processing  │            │  - Raw flow DB       │
│  - MAC tracking    │            │                      │
│  - Topology map    │            └──────────┬───────────┘
└─────────┬──────────┘                       │
          │                                  │
          │ SQLite                           │ SQLite
          │ /ramdisk/snmpqserver.db          │ /ramdisk/nfacctd.db
          │                                  │
          └────────┬─────────────────────────┘
                   │                       ▲
                   │                       │
                   ▼                       │
          ┌────────────────────┐           │
          │netflowProcessor.py │───────────┘
          │(Flow Categorizer)  │
          │                    │ SQLite
          │ - Classifies flows │ /ramdisk/netflow.db
          │ - Public/Private   │
          │ - Up/Down stream   │
          └─────────┬──────────┘
                    │
                    │ Reads
                    ▼
          ┌──────────────────────┐
          │ flask_web_server.py  │
          │  (Web Dashboard)     │
          │                      │
          │  - Device queries    │
          │  - NetFlow stats     │
          │  - Topology view     │
          └──────────────────────┘
                    │
                    │ HTTP (Port 5000)
                    ▼
          ┌──────────────────────┐
          │    Web Browser       │
          │   (User Interface)   │
          └──────────────────────┘
```

## Configuration

### SNMP Community Strings
On Cisco routers, ensure you have SNMP v2c configured:
```
snmp-server community YOUR-COMMUNITY-STRING RO
```

### NetFlow Export Configuration
On Cisco routers:
```
flow exporter SNMPQUERY-EXPORTER
 destination YOUR-SERVER-IP
 transport udp 2055
 
flow monitor SNMPQUERY-MONITOR
 exporter SNMPQUERY-EXPORTER
 record netflow ipv4 original-input
 
interface GigabitEthernet0/0
 ip flow monitor SNMPQUERY-MONITOR input
```

### Security Considerations

⚠️ **IMPORTANT SECURITY NOTES:**

1. **Change default credentials** in `flask_web_server.py`
2. **Use environment variables** for sensitive configuration:
   ```bash
   export FLASK_SECRET_KEY='generate-with-python-secrets-token-hex'
   export SNMP_COMMUNITY='your-read-only-community'
   ```
3. **Restrict network access** - Run behind a firewall or VPN
4. **Use read-only SNMP** community strings only
5. **Regular updates** - Keep dependencies updated

## Project Status

🟢 **Production Use**: Currently deployed at 2 sites, with 2 more planned

This software is actively maintained and used in production environments. However, it has been primarily tested with:
- Cisco ISR 4000, 1900 and 2800 series routers
- Various L2 managed switches supporting SNMP
- Ubiquiti UniFi devices

**Testing needed for:**
- MikroTik routers
- TP-Link Omada ecosystem
- Juniper devices
- HP/Aruba switches
- etc.

If you test SnmpQuery with other hardware, please share your findings!

## Contributing

Contributions are welcome! Whether you:
- 🐛 Found a bug
- 💡 Have a feature idea  
- 📝 Want to improve documentation
- 🧪 Tested on new hardware
- 🌍 Want to add translations

Please open an issue or submit a pull request.

### Development Setup
```bash
git clone https://github.com/agmaiztegui/SnmpQuery.git
cd snmpquery
pip3 install -r requirements.txt
# Make your changes
# Test thoroughly
# Submit PR with description of changes
```

## License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPLv3)**.

This means:
- ✅ You can use this software freely for any purpose
- ✅ You can modify and distribute modified versions
- ✅ You can use it commercially
- ⚠️ If you modify and deploy this on a network/server, you **must** provide source code to users
- ⚠️ All derivative works must also be AGPLv3

**Why AGPLv3?** This license ensures that if companies use and improve this software, they must share those improvements back with the community, preventing the "SaaS loophole" where cloud providers could use GPL code without contributing back.

See [LICENSE](LICENSE) file for full details.

### Third-Party Licenses
- Flask: BSD-3-Clause
- Flask-Login: MIT
- prompt_toolkit: BSD-3-Clause
- net-snmp: Various BSD-style
- pmacct: GPLv2+

All dependencies are compatible with AGPLv3.

## Credits

**Created by:** Agustin Garcia Maiztegui

Built to solve real-world problems in small business network management. If this tool helps your organization, consider:
- ⭐ Starring the repository
- 📢 Sharing with colleagues
- 🐛 Reporting bugs or suggesting features
- 💻 Contributing improvements

## Support & Contact

- **Issues:** [GitHub Issues](https://github.com/agmaiztegui/snmpquery/issues)
- **Discussions:** [GitHub Discussions](https://github.com/agmaiztegui/snmpquery/discussions)

## Acknowledgments

- The pmacct project for NetFlow collection
- Net-SNMP project for SNMP tools
- The open-source community

## Roadmap

Planned features:
- [ ] Machine Learning Analisys
- [ ] Historical Data
- [ ] Support for SNMPv3

---

**Disclaimer:** This software is provided "as is" without warranty of any kind. Always test in a non-production environment first and ensure you have proper backups and change control procedures.
