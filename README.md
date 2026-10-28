# GuardianBees Beta

**Real-time home network anomaly detection powered by AI**

Detect unusual network behavior in seconds. GuardianBees monitors your network traffic using Meta's AI models to identify threats, suspicious devices, and potential security issues—all running locally on your machine.

## Features

**Real-time Anomaly Detection**
- Monitors network packets in real-time
- AI-powered pattern recognition using Meta's Muse Spark Open
- Detects behavioral anomalies within seconds

**Privacy-First**
- All processing happens locally, zero data sent to external servers or machines
- Network analysis stays on your machine
- No cloud dependencies required

**Lightweight**
- Runs on Raspberry Pi, old laptops, or any Linux machine
- Minimal resource usage
- CLI-based for efficiency

**Practical Use Cases**
- Detect ransomware or malware communication attempts
- Monitor for unusual device behavior
- Identify unauthorized network access
- Network surveillance for home/small business

## How It Works

```
Network Traffic → Packet Capture → Feature Extraction → AI Analysis → Alerts
                    (scapy)           (statistics)     (Muse Spark)   (JSON)
```

1. **Captures** network packets from your interface
2. **Extracts** meaningful features (IPs, ports, protocols, patterns)
3. **Analyzes** with Meta's Muse Spark Open model running locally
4. **Alerts** you when anomalies are detected
5. **Logs** everything for later review

## Requirements

- **Python 3.8+**
- **Ollama** (for running Muse Spark Open locally)
- **Linux/macOS** (primary support; Windows via WSL)
- **Network interface access** (may require sudo)

## Quick Start

### 1. Install Ollama

Download and install from [ollama.ai](https://ollama.ai)

```bash
# macOS
brew install ollama

# Linux
curl https://ollama.ai/install.sh | sh
```

### 2. Pull the Meta Model

```bash
ollama pull meta-models/muse-spark-open-1026
```

### 3. Start Ollama Server

```bash
ollama serve
# Runs on http://localhost:11434
```

### 4. Install GuardianBees

```bash
git clone https://github.com/yourusername/GuardianBees-beta.git
cd GuardianBees-beta
pip install -r requirements.txt
```

### 5. Run the Sniffer

```bash
sudo python sniffer.py
# (sudo required for packet capture)
```

You should see output like:

```
[2026-10-29 10:15:23] Starting GuardianBees Beta...
[2026-10-29 10:15:24] Connected to Ollama at localhost:11434
[2026-10-29 10:15:25] Listening on eth0...
[2026-10-29 10:15:47] Analyzing packets...
[2026-10-29 10:16:12] 🚨 ALERT: Unusual port access detected from 192.168.1.50
  Reason: Device connecting to rare port 8080
  Confidence: 7/10
```

Alerts are saved to `alerts.json`.

## Project Structure

```
GuardianBees-beta/
├── sniffer.py          # Main packet capture + analysis loop
├── analyzer.py         # Feature extraction + Muse Spark integration
├── alerts.py           # Alert generation and logging
├── requirements.txt    # Python dependencies
├── README.md           # This file
└── LICENSE             # MIT License
```

## Configuration

Create a `.env` file to customize behavior (optional):

```
NETWORK_INTERFACE=eth0
OLLAMA_URL=http://localhost:11434
ALERT_THRESHOLD=6
FEATURE_EXTRACTION_INTERVAL=10
```

## Output

All alerts are saved to `alerts.json`:

```json
{
  "alerts": [
    {
      "timestamp": "2026-10-29T10:16:12Z",
      "device_ip": "192.168.1.50",
      "anomaly_type": "unusual_port_access",
      "description": "Device connecting to rare port 8080",
      "confidence": 7,
      "raw_data": {
        "ports": [8080, 443, 80],
        "protocol_shift": 0.45,
        "volume_deviation": 2.1
      }
    }
  ]
}
```

## Limitations & Known Issues

⚠️ **This is a beta release**

- **No UI yet** — CLI only for now
- **Feature extraction** is basic — only learns from your current network
- **Ollama required** — must run locally (no API fallback yet)
- **Linux/macOS only** — Windows support planned
- **Requires root/sudo** — packet capture needs elevated privileges

## Future Roadmap

- [ ] Web dashboard for alerts
- [ ] Historical trend analysis
- [ ] IP blocking integration
- [ ] Parental controls module
- [ ] Multi-device coordination (swarm mode)
- [ ] Windows support
- [ ] Custom model training

## Technology Stack

- **Packet Capture:** Scapy
- **AI Model:** Meta's Muse Spark Open (via Ollama)
- **Storage:** JSON + SQLite
- **Language:** Python 3.8+

## Contributing

GuardianBees Beta is open source under the MIT License. Contributions welcome!

```bash
git clone <repo>
git checkout -b feature/your-feature
git commit -m "Add your feature"
git push origin feature/your-feature
```

Then open a Pull Request.

## License

MIT License — See [LICENSE](LICENSE) file for details.

**Free for personal, educational, and non-commercial use.**

## Support

- **Issues:** GitHub Issues
- **Discussions:** GitHub Discussions
- **Email:** clement.duboille@gmail.com

## About

**GuardianBees** is built for the Meta Global AI Developer Hackathon 2026.

Inspired by the need for accessible, intelligent home network security using cutting-edge AI models.

---

**Status:** Beta (actively developed during hackathon)

**Last Updated:** October 29, 2026

**Author:** DarkWhige
