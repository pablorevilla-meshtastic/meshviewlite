# meshviewlite

Single-script MQTT collector that stores only:
- `nodes` (latest node state)
- `packets` (raw packet log)

No `packet_seen` table is used.

## Setup

```bash
cd /home/pablo/dev/meshviewlite
python -m venv env
./env/bin/pip install -r requirements.txt
```

## Run

```bash
./env/bin/python meshviewlite.py \
  --broker mqtt.example.org \
  --port 1883 \
  --topic '#' \
  --db meshviewlite.db
```

Using a quick config file (`meshviewlite.toml`):

```toml
[mqtt]
broker = "mqtt.example.org"
port = 1883
topic = "#"
db = "meshviewlite.db"
username = "user"
password = "pass"
client_id = "meshviewlite"
keepalive = 60
retention_days = 14
purge_hour_utc = 3
log_packets = false
tls = false
insecure_tls = false
payload_format = "json" # json | meshtastic | auto

[meshtastic]
primary_key_b64 = "1PG7OiApB1nwvP+rz05pAQ=="
secondary_key_b64 = ["base64Key1==", "base64Key2=="]
skip_node_ids = ["0x1234", "5678"]
```

You can also start from the included template: `meshviewlite.toml.example`.

Run with config:

```bash
./env/bin/python meshviewlite.py --config meshviewlite.toml
```

CLI flags override config values, for example:

```bash
./env/bin/python meshviewlite.py --config meshviewlite.toml --topic 'msh/US/2/e/#'
```

For booleans you can force-disable values from config with `--no-tls` or `--no-insecure-tls`.

Optional auth/TLS:

```bash
./env/bin/python meshviewlite.py \
  --broker mqtt.example.org \
  --port 8883 \
  --topic '#' \
  --db meshviewlite.db \
  --username user \
  --password pass \
  --tls
```

Meshtastic protobuf payloads (with decryption keys):

```bash
./env/bin/python meshviewlite.py \
  --broker mqtt.example.org \
  --port 1883 \
  --topic 'msh/US/2/e/#' \
  --db meshviewlite.db \
  --username user \
  --password pass \
  --payload-format meshtastic \
  --primary-key-b64 '1PG7OiApB1nwvP+rz05pAQ==' \
  --secondary-key-b64 'base64Key1==,base64Key2==' \
  --skip-node-id 0x1234 \
  --skip-node-id 5678
```

Payload decode modes:
- `--payload-format json`: expects JSON payloads (default)
- `--payload-format meshtastic`: expects Meshtastic `ServiceEnvelope` protobuf payloads
- `--payload-format auto`: try JSON first, then Meshtastic protobuf

## Notes

- `nodes.id` is the primary key (upsert on every packet with node info/telemetry/position).
- Every JSON payload is stored in `packets.payload_json`.
- Script handles SIGINT/SIGTERM and closes DB cleanly.

## Web UI

Simple frontend (node list + node detail page similar to Meshview node view):

```bash
./env/bin/python meshviewlite_web.py --config meshviewlite.toml
```

If you pull new changes, reinstall deps once to ensure Jinja is available:

```bash
./env/bin/pip install -r requirements.txt
```

Then open:

- `http://127.0.0.1:8050/` (node list)
- `http://127.0.0.1:8050/node/<node_id>` (node details, map, recent packets)
- `http://127.0.0.1:8050/api/nodes` (nodes API)
- `http://127.0.0.1:8050/api/packets` (packets API)

Optional overrides:

```bash
./env/bin/python meshviewlite_web.py --config meshviewlite.toml --host 0.0.0.0 --port 8050
```

API example:

```bash
curl -s http://127.0.0.1:8050/api/nodes | jq .
```

Packets API examples:

```bash
curl -s "http://127.0.0.1:8050/api/packets?node_id=1254677894&limit=100" | jq .
curl -s "http://127.0.0.1:8050/api/packets?from_node_id=1254677894&portnum=67&since=1735689600000000&limit=500" | jq .
```

Supported query params for `/api/packets`:
- `node_id`: packets where `from_id == node_id OR to_id == node_id`
- `from_node_id`: packets where `from_id == from_node_id`
- `portnum`: numeric port filter (also maps common packet type names like telemetry/position/nodeinfo/neighbor)
- `since`: epoch seconds or microseconds
- `limit`: max rows (1..5000, default 200)
