# GuardianBees Beta

GuardianBees is a Python backend that detects unusual network behavior. It
captures traffic, aggregates it into behavioral features, scores those features
with an Isolation Forest, and sends only detected anomalies to Meta Model API
for a human-readable security assessment.

## Runtime pipeline

```text
Network packets
      |
      v
Scapy sniffer
      |
      v
Normalized packet events
      |
      v
30-second aggregation per source IP
      |
      v
Traffic history (data/traffic.jsonl)
      |
      v
Isolation Forest anomaly detection
      |
      +---- normal behavior allow-list --> skip Meta
      |
      v
Meta Model API analysis
      |
      v
JSON alert printed by the backend
```

### 1. Backend startup

`server.py` starts a FastAPI application with Uvicorn. During application
startup, `AnalyzerRuntime`:

1. Loads the retained traffic history.
2. Trains an Isolation Forest when at least two records are available.
3. Starts the network sniffer in a background thread.

If there is not enough history, the server still starts, but live windows are
only logged until the detector is trained. Training can also be requested later
with `POST /analyzer/train`.

### 2. Network sniffing

`functions/DataProcess/sniffer.py` uses Scapy to capture IPv4 packets. Each
packet is converted into a normalized event containing:

- timestamp, source and destination IP;
- protocol and ports;
- TCP SYN information;
- direction;
- DNS query name;
- packet size.

Packet capture normally requires `NET_RAW`, `NET_ADMIN`, or equivalent host
permissions.

### 3. Processing and aggregation

`functions/DataProcess/agregator.py` groups events into 30-second windows per
source IP. It calculates requests, unique ports, destinations and protocols,
bytes, SYN requests, direction counts, and DNS query information.

### 4. Storage

`functions/logger.py` appends aggregated windows to
`data/traffic.jsonl`. Records older than 30 days are removed when the log is
updated. Docker mounts `./data` so traffic history, Meta usage information, and
the normal-behavior list survive container recreation.

### 5. Isolation Forest analysis

`functions/analyzer.py` trains `sklearn.ensemble.IsolationForest` from the
numeric features in the retained traffic history. Each new window receives an
anomaly score and is marked as anomalous when the model predicts `-1`.

Models are saved as timestamped files in `models/`. The latest trained model is
kept in memory and used for live windows.

### 6. Meta analysis

Only anomalous windows are passed to `functions/AI/MetaAI.py`. The client sends
aggregated metrics, not raw packets, to Meta Model API. Meta is asked to return:

- `is_alert`;
- `danger_score` from 0 to 10;
- `severity` (`low`, `medium`, `high`, or `critical`);
- a short `summary`;
- one concrete `action`.

Calls are limited by `META_AI_MAX_CALLS_PER_DAY` and counted in
`data/meta_ai_usage.json`. A normal-behavior allow-list can skip Meta entirely
for behavior patterns confirmed as safe by the user.

## Requirements

- Docker and Docker Compose
- Linux host recommended for packet capture
- A Meta Model API key
- A network interface accessible to the Docker host

## Configuration

Create `.env` next to `docker-compose.yml`:

```env
MODEL_API_KEY=your_meta_model_api_key
META_AI_MODEL=muse-spark-1.3
META_AI_MAX_CALLS_PER_DAY=100
NETWORK_INTERFACE=eth0
```

`.env` is ignored by Git. Use plain values; do not write Docker interpolation
expressions such as `META_AI_MAX_CALLS_PER_DAY:-100` in this file.

`docker-compose.yml` loads `.env` into the container with `env_file`. The
Compose service uses host networking and adds packet-capture capabilities.

## Run with Docker

Build and start the backend:

```bash
./scripts/run/run_dev.sh
```

Use `--build` after changing Python code so the image contains the latest
source files. Stop the service with:

```bash
docker compose down
```

The API listens on `http://localhost:8000`.

## Backend routes

### Health

```http
GET /health
```

Returns:

```json
{"status": "ok"}
```

### Train the detector

```http
POST /analyzer/train
```

Trains a new Isolation Forest from the retained traffic history and saves it
under `models/`.

### Detector status

```http
GET /analyzer/status
```

Returns whether a model is loaded, the number of training records, and its path.

### Test Meta manually

```http
POST /ai/test
Content-Type: application/json
```

An empty JSON object uses the route defaults:

```json
{}
```

The response contains the selected model and the structured Meta analysis.

### Confirm a behavior as normal

```http
POST /ai/normal-behaviors
Content-Type: application/json
```

Send the same aggregated metrics as `/ai/test`. The behavior is persisted in
`data/normal_behaviors.json`. Future matching anomaly alerts skip the Meta
request.

### List normal behaviors

```http
GET /ai/normal-behaviors
```

Returns the behavior signatures currently excluded from Meta analysis.

## Project structure

```text
GuardianBees-beta/
├── server.py                         # FastAPI/Uvicorn entrypoint
├── route/
│   ├── base.py                       # Health route
│   ├── analyzer.py                   # Training and detector status routes
│   └── aiTests.py                    # Meta test and normal-behavior routes
├── functions/
│   ├── analyzer.py                   # Runtime, training, scoring, sniffer loop
│   ├── alerts.py                     # Alert creation and Meta dispatch
│   ├── normalBehaviors.py            # Persistent normal-behavior allow-list
│   ├── logger.py                     # Traffic history persistence
│   ├── AI/MetaAI.py                  # Meta Model API client
│   └── DataProcess/
│       ├── sniffer.py                # Scapy packet capture
│       ├── agregator.py              # Window aggregation
│       └── features.py               # Model feature definitions
├── data/                             # Persistent traffic and runtime state
├── models/                           # Versioned Isolation Forest models
├── docker-compose.yml
├── Dockerfile
└── requirements.txt
```

## Alert behavior

An alert is emitted as a JSON record on the backend logs. It includes the
source IP, time window, anomaly score, observed aggregated metrics, and—when
enabled and available—the Meta analysis. If a matching behavior is in the
normal-behavior list, the alert is marked as normal and Meta is not called.

## Limitations

- This is a beta detector and can produce false positives.
- Isolation Forest quality depends on the retained local baseline.
- Meta analysis requires network access and a valid API key.
- Only aggregated network metadata is sent to Meta; raw packets are not sent.
- Packet capture support is primarily intended for Linux with host networking.

## License

MIT License. See [LICENSE](./LICENSE).
