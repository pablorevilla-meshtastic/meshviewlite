#!/usr/bin/env python3
"""meshviewlite MQTT collector.

High-level flow:
1. Parse CLI/TOML settings.
2. Initialize SQLite schema and indexes.
3. Connect to MQTT and consume messages.
4. Decode payload (JSON or Meshtastic envelope).
5. Store packet row (deduped by packet_id).
6. Upsert latest node state (nodeinfo/telemetry/position).
7. Periodically purge old packets (retention policy).
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import signal
import socket
import sqlite3
import sys
import time
import tomllib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from google.protobuf import json_format
from google.protobuf.message import DecodeError
from meshtastic.protobuf.config_pb2 import Config
from meshtastic.protobuf.mesh_pb2 import Data
from meshtastic.protobuf.mesh_pb2 import HardwareModel
from meshtastic.protobuf.mesh_pb2 import Position
from meshtastic.protobuf.mesh_pb2 import User
from meshtastic.protobuf.mqtt_pb2 import ServiceEnvelope
from meshtastic.protobuf.portnums_pb2 import PortNum
from meshtastic.protobuf.telemetry_pb2 import Telemetry
import paho.mqtt.client as mqtt

PACKET_RETENTION_DAYS = 14
PURGE_HOUR_UTC = 3


# Port number -> human label map used when packet_type needs inference.
PORTNUM_NAMES: dict[int, str] = {
    0: "Unknown",
    1: "Text",
    2: "Remote Hardware",
    3: "Position",
    4: "Node Info",
    5: "Routing",
    6: "Admin",
    7: "Text (Compressed)",
    8: "Waypoint",
    9: "Audio",
    10: "Detection Sensor",
    11: "Alert",
    12: "Key Verification",
    32: "Reply",
    33: "IP Tunnel",
    34: "Paxcounter",
    35: "Store Forward++",
    36: "Node Status",
    64: "Serial",
    65: "Store & Forward",
    66: "Range Test",
    67: "Telemetry",
    68: "ZPS",
    69: "Simulator",
    70: "Traceroute",
    71: "Neighbor",
    72: "ATAK",
    73: "Map Report",
    74: "Power Stress",
    76: "Reticulum Tunnel",
    77: "Cayenne",
    256: "Private App",
    257: "ATAK Forwarder",
}


@dataclass
class Settings:
    broker: str
    port: int
    topic: str
    db_path: Path
    username: str | None
    password: str | None
    client_id: str
    keepalive: int
    tls: bool
    insecure_tls: bool
    payload_format: str
    primary_key: bytes | None
    skip_node_ids: set[int]
    retention_days: int
    purge_hour_utc: int
    log_packets: bool
    log_decoded: bool
    verbose_mqtt: bool


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def _parse_node_ids(values: list[str]) -> set[int]:
    node_ids: set[int] = set()
    for raw in values:
        for item in raw.split(","):
            value = item.strip()
            if not value:
                continue
            try:
                node_ids.add(int(value, 0))
            except ValueError as exc:
                raise argparse.ArgumentTypeError(f"Invalid node id '{value}': {exc}") from exc
    return node_ids


def _parse_b64_keys(values: list[str], option_name: str) -> list[bytes]:
    keys: list[bytes] = []
    for raw in values:
        for item in raw.split(","):
            value = _strip_quotes(item.strip())
            if not value:
                continue
            try:
                decoded = base64.b64decode(value, validate=True)
            except ValueError as exc:
                raise argparse.ArgumentTypeError(
                    f"Invalid base64 value for {option_name}: '{item.strip()}'"
                ) from exc
            if len(decoded) not in (16, 24, 32):
                raise argparse.ArgumentTypeError(
                    f"Invalid AES key length for {option_name}: got {len(decoded)} bytes "
                    f"(expected 16, 24, or 32)"
                )
            keys.append(decoded)
    return keys


def _to_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value]
    return [str(value)]


def _get_cfg_section(config: dict[str, Any], section: str) -> dict[str, Any]:
    value = config.get(section)
    return value if isinstance(value, dict) else {}


def _cfg_value(
    config: dict[str, Any],
    key: str,
    *,
    section: str | None = None,
    aliases: tuple[str, ...] = (),
) -> Any:
    if section:
        section_data = _get_cfg_section(config, section)
        for name in (key, *aliases):
            if name in section_data:
                return section_data[name]
    for name in (key, *aliases):
        if name in config:
            return config[name]
    return None


def load_config(config_path: Path | None) -> dict[str, Any]:
    """Load optional TOML config file."""
    if config_path is None:
        return {}
    with config_path.open("rb") as fh:
        loaded = tomllib.load(fh)
    if not isinstance(loaded, dict):
        raise argparse.ArgumentTypeError("Config file must contain a TOML table at top level")
    return loaded


def parse_args() -> Settings:
    """Merge CLI args and TOML values into a normalized Settings object."""
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--config", default=None, help="TOML config path")
    pre_args, _ = pre.parse_known_args()
    config_path = Path(pre_args.config) if pre_args.config else None
    try:
        config = load_config(config_path)
    except (OSError, tomllib.TOMLDecodeError, argparse.ArgumentTypeError) as exc:
        raise SystemExit(f"Failed to load config: {exc}") from exc

    parser = argparse.ArgumentParser(
        description="meshviewlite: collect nodes + packets from MQTT into SQLite."
    )
    parser.add_argument("--config", default=pre_args.config, help="TOML config path")
    parser.add_argument(
        "--broker",
        default=_cfg_value(config, "broker", section="mqtt"),
        help="MQTT broker host",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=_cfg_value(config, "port", section="mqtt") or 1883,
        help="MQTT broker port",
    )
    parser.add_argument(
        "--topic",
        default=_cfg_value(config, "topic", section="mqtt") or "#",
        help="MQTT topic filter (default: #)",
    )
    parser.add_argument(
        "--db",
        default=_cfg_value(config, "db", section="mqtt") or "meshviewlite.db",
        help="SQLite DB path",
    )
    parser.add_argument(
        "--username",
        default=_cfg_value(config, "username", section="mqtt"),
        help="MQTT username",
    )
    parser.add_argument(
        "--password",
        default=_cfg_value(config, "password", section="mqtt"),
        help="MQTT password",
    )
    parser.add_argument(
        "--client-id",
        default=_cfg_value(config, "client_id", section="mqtt", aliases=("client-id",))
        or "meshviewlite",
        help="MQTT client ID",
    )
    parser.add_argument(
        "--keepalive",
        type=int,
        default=_cfg_value(config, "keepalive", section="mqtt") or 60,
        help="MQTT keepalive seconds",
    )
    parser.add_argument(
        "--tls",
        action=argparse.BooleanOptionalAction,
        default=bool(_cfg_value(config, "tls", section="mqtt") or False),
        help="Use TLS",
    )
    parser.add_argument(
        "--insecure-tls",
        action=argparse.BooleanOptionalAction,
        default=bool(_cfg_value(config, "insecure_tls", section="mqtt", aliases=("insecure-tls",)) or False),
        help="Disable TLS cert verification (not recommended)",
    )
    parser.add_argument(
        "--payload-format",
        choices=("json", "meshtastic", "auto"),
        default=_cfg_value(config, "payload_format", section="mqtt", aliases=("payload-format",))
        or "json",
        help="Payload decode mode (default: json)",
    )
    parser.add_argument(
        "--primary-key-b64",
        default=_cfg_value(
            config,
            "primary_key_b64",
            section="meshtastic",
            aliases=("primary-key-b64",),
        ),
        help="Primary Meshtastic AES key (base64), used for encrypted packets",
    )
    parser.add_argument(
        "--skip-node-id",
        action="append",
        default=_to_str_list(
            _cfg_value(
                config,
                "skip_node_id",
                section="meshtastic",
                aliases=("skip-node-id", "skip_node_ids"),
            )
        ),
        help="Node ID(s) to ignore (repeat or comma-separate, accepts decimal/hex)",
    )
    parser.add_argument(
        "--retention-days",
        type=int,
        default=_cfg_value(config, "retention_days", section="mqtt", aliases=("retention-days",))
        or PACKET_RETENTION_DAYS,
        help=f"Delete packets older than this many days (default: {PACKET_RETENTION_DAYS})",
    )
    parser.add_argument(
        "--purge-hour-utc",
        type=int,
        default=_cfg_value(config, "purge_hour_utc", section="mqtt", aliases=("purge-hour-utc",))
        or PURGE_HOUR_UTC,
        help=f"UTC hour (0-23) for daily purge (default: {PURGE_HOUR_UTC})",
    )
    parser.add_argument(
        "--log-packets",
        action=argparse.BooleanOptionalAction,
        default=bool(_cfg_value(config, "log_packets", section="mqtt", aliases=("log-packets",)) or False),
        help="Log one line per received packet to console",
    )
    parser.add_argument(
        "--log-decoded",
        action=argparse.BooleanOptionalAction,
        default=bool(_cfg_value(config, "log_decoded", section="mqtt", aliases=("log-decoded",)) or False),
        help="Print decoded packet payload JSON for successfully decoded packets",
    )
    parser.add_argument(
        "--verbose-mqtt",
        action=argparse.BooleanOptionalAction,
        default=bool(_cfg_value(config, "verbose_mqtt", section="mqtt", aliases=("verbose-mqtt",)) or False),
        help="Verbose MQTT diagnostics (subscribe ACKs, disconnects, decode skips)",
    )

    args = parser.parse_args()
    if not args.broker:
        parser.error("MQTT broker is required. Set --broker or provide it in --config.")

    primary_key = None
    if args.primary_key_b64:
        parsed = _parse_b64_keys([args.primary_key_b64], "--primary-key-b64")
        primary_key = parsed[0]

    skip_node_ids = _parse_node_ids(args.skip_node_id)
    if args.retention_days < 1:
        parser.error("--retention-days must be >= 1")
    if args.purge_hour_utc < 0 or args.purge_hour_utc > 23:
        parser.error("--purge-hour-utc must be between 0 and 23")

    return Settings(
        broker=args.broker,
        port=args.port,
        topic=args.topic,
        db_path=Path(args.db),
        username=args.username,
        password=args.password,
        client_id=args.client_id,
        keepalive=args.keepalive,
        tls=args.tls,
        insecure_tls=args.insecure_tls,
        payload_format=args.payload_format,
        primary_key=primary_key,
        skip_node_ids=skip_node_ids,
        retention_days=args.retention_days,
        purge_hour_utc=args.purge_hour_utc,
        log_packets=args.log_packets,
        log_decoded=args.log_decoded,
        verbose_mqtt=args.verbose_mqtt,
    )


def init_db(conn: sqlite3.Connection) -> None:
    """Create/migrate SQLite tables and indexes used by the collector."""
    desired_nodes_columns = [
        "id",
        "longname",
        "shortname",
        "role",
        "channel",
        "hw_model",
        "last_lat",
        "last_lon",
        "last_seen",
        "payload",
    ]
    existing_nodes_columns = [r[1] for r in conn.execute("PRAGMA table_info(nodes)").fetchall()]
    if existing_nodes_columns and existing_nodes_columns != desired_nodes_columns:
        conn.execute("DROP TABLE nodes")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS nodes (
            id INTEGER PRIMARY KEY,
            longname TEXT,
            shortname TEXT,
            role TEXT,
            channel TEXT,
            hw_model TEXT,
            last_lat INTEGER,
            last_lon INTEGER,
            last_seen INTEGER,
            payload TEXT NOT NULL
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            packet_id INTEGER NOT NULL,
            received_at INTEGER NOT NULL,
            topic TEXT NOT NULL,
            packet_type TEXT,
            from_id TEXT,
            to_id TEXT,
            channel TEXT,
            portnum TEXT,
            payload_json TEXT NOT NULL
        )
        """
    )
    packet_cols = {r[1] for r in conn.execute("PRAGMA table_info(packets)").fetchall()}
    if "packet_id" not in packet_cols:
        conn.execute("ALTER TABLE packets ADD COLUMN packet_id INTEGER")
    # Normalize legacy DBs before adding unique index:
    # keep one row per packet_id and drop duplicates.
    conn.execute(
        """
        DELETE FROM packets
        WHERE packet_id IS NOT NULL
          AND id NOT IN (
            SELECT MIN(id)
            FROM packets
            WHERE packet_id IS NOT NULL
            GROUP BY packet_id
          )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_packets_received_at ON packets(received_at)")
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_packets_packet_id_unique "
        "ON packets(packet_id) WHERE packet_id IS NOT NULL"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_packets_topic ON packets(topic)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_packets_from_id ON packets(from_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_nodes_last_seen ON nodes(last_seen)")
    conn.commit()


def as_text(value: Any) -> str | None:
    """Convert simple scalar values to string; return None for unsupported types."""
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    return None


def packet_field(payload: dict[str, Any], *names: str) -> Any:
    """Get a field from top-level payload, then payload.packet, then payload.packet.decoded."""
    packet = payload.get("packet") if isinstance(payload.get("packet"), dict) else {}
    decoded = packet.get("decoded") if isinstance(packet.get("decoded"), dict) else {}
    for name in names:
        if name in payload:
            return payload.get(name)
    for name in names:
        if name in packet:
            return packet.get(name)
    for name in names:
        if name in decoded:
            return decoded.get(name)
    return None


def infer_channel(topic: str) -> str | None:
    """Infer mesh channel name from MQTT topic structure."""
    def _is_node_hex(value: str) -> bool:
        return re.fullmatch(r"![0-9a-fA-F]{8}", value) is not None

    parts = [p for p in topic.split("/") if p]
    if not parts:
        return None
    if "e" in parts:
        idx = parts.index("e")
        if idx + 1 < len(parts):
            candidate = parts[idx + 1]
            if not _is_node_hex(candidate):
                return candidate

    # Common JSON topic form:
    # .../json/<channel>/!<sender_hex>
    if len(parts) >= 2 and _is_node_hex(parts[-1]):
        candidate = parts[-2]
        if candidate and not _is_node_hex(candidate):
            return candidate

    candidate = parts[-1]
    if _is_node_hex(candidate):
        return None
    return candidate


def infer_packet_type(payload: dict[str, Any]) -> str | None:
    """Infer packet type from explicit fields or decoded port number."""
    def _port_name(value: Any) -> str | None:
        if isinstance(value, (int, float)):
            return PORTNUM_NAMES.get(int(value))
        if isinstance(value, str):
            stripped = value.strip()
            enum_map = {
                "TEXT_MESSAGE_APP": "Text",
                "POSITION_APP": "Position",
                "NODEINFO_APP": "Node Info",
                "TELEMETRY_APP": "Telemetry",
            }
            mapped = enum_map.get(stripped.upper())
            if mapped:
                return mapped
            try:
                return PORTNUM_NAMES.get(int(stripped, 10))
            except ValueError:
                return None
        return None

    for key in ("type", "packet_type", "event", "kind"):
        t = as_text(packet_field(payload, key))
        if t:
            return t
    packet = payload.get("packet") if isinstance(payload.get("packet"), dict) else {}
    decoded = payload.get("decoded")
    if not isinstance(decoded, dict):
        decoded = packet.get("decoded")
    if isinstance(decoded, dict):
        raw_port = decoded.get("portnum") or decoded.get("port_num")
        name = _port_name(raw_port)
        if name:
            return name
        t = as_text(raw_port)
        if t:
            return t
    return None


def infer_node(payload: dict[str, Any], channel: str | None) -> dict[str, Any] | None:
    """Extract node update fields from supported packet types.

    Supported packet types:
    - nodeinfo: names/model/role
    - position/location: latitude/longitude
    - telemetry: only last_seen and raw payload are updated by upsert
    """
    nested_payload = payload.get("payload") if isinstance(payload.get("payload"), dict) else {}
    packet_type_raw = payload.get("type")
    packet_type = (
        str(packet_type_raw).strip().lower().replace("_", "").replace(" ", "").replace("(", "").replace(")", "")
        if packet_type_raw is not None
        else ""
    )
    if packet_type not in {"nodeinfo", "telemetry", "position", "location", "text"}:
        return None

    def _enum_name(enum_type: Any, value: Any) -> str | None:
        if isinstance(value, (int, float)):
            try:
                return enum_type.Name(int(value))
            except Exception:
                return str(int(value))
        return as_text(value)

    def _normalize_node_id(value: Any) -> int | None:
        text = as_text(value)
        if not text:
            return None
        text = text.strip()
        if text.startswith("!"):
            try:
                return int(text[1:], 16)
            except ValueError:
                return None
        try:
            return int(text, 10)
        except ValueError:
            return None

    def _clean_channel(value: Any) -> str | None:
        text = as_text(value)
        if not text:
            return None
        stripped = text.strip()
        if not stripped:
            return None
        if re.fullmatch(r"![0-9a-fA-F]{8}", stripped):
            return None
        if stripped == "0":
            return None
        return stripped

    # Source node identity can be top-level (`from`) or nested (`packet.from`).
    node_id = _normalize_node_id(packet_field(payload, "from", "from_id", "fromId"))
    # NodeInfo may also contain user id like "!9ea14748".
    if node_id is None and packet_type == "nodeinfo":
        node_id = _normalize_node_id(
            nested_payload.get("id") or nested_payload.get("user_id") or nested_payload.get("node_id")
        )
    if not node_id:
        return None

    long_name: str | None = None
    short_name: str | None = None
    hw_model: str | None = None
    role: str | None = None
    lat: Any = None
    lon: Any = None

    if packet_type == "nodeinfo":
        long_name = as_text(nested_payload.get("longname") or nested_payload.get("long_name"))
        short_name = as_text(nested_payload.get("shortname") or nested_payload.get("short_name"))
        hw_model = _enum_name(HardwareModel, nested_payload.get("hardware") or nested_payload.get("hw_model"))
        role = _enum_name(Config.DeviceConfig.Role, nested_payload.get("role"))
    elif packet_type in {"position", "location"}:
        lat = nested_payload.get("latitude_i", nested_payload.get("latitude"))
        lon = nested_payload.get("longitude_i", nested_payload.get("longitude"))

    if isinstance(lat, (int, float)):
        if abs(float(lat)) <= 180:
            lat = int(round(float(lat) * 10_000_000))
        else:
            lat = int(round(float(lat)))
    if isinstance(lon, (int, float)):
        if abs(float(lon)) <= 180:
            lon = int(round(float(lon) * 10_000_000))
        else:
            lon = int(round(float(lon)))

    channel_value = _clean_channel(payload.get("channel")) or _clean_channel(channel)

    return {
        "id": node_id,
        "longname": long_name,
        "shortname": short_name,
        "hw_model": hw_model,
        "role": role,
        "channel": channel_value,
        "last_lat": lat if isinstance(lat, int) else None,
        "last_lon": lon if isinstance(lon, int) else None,
    }


def store_packet(conn: sqlite3.Connection, topic: str, payload: dict[str, Any]) -> None:
    """Insert packet row if packet_id is present and not already stored."""
    now = int(time.time())
    channel = infer_channel(topic)
    packet_type = infer_packet_type(payload)
    packet_id_raw = packet_field(payload, "id")
    packet_id: int | None = None
    if isinstance(packet_id_raw, (int, float)):
        packet_id = int(packet_id_raw)
    elif isinstance(packet_id_raw, str):
        try:
            packet_id = int(packet_id_raw.strip(), 10)
        except ValueError:
            packet_id = None
    if packet_id is None:
        return
    from_id = as_text(packet_field(payload, "from", "from_id", "fromId"))
    to_id = as_text(packet_field(payload, "to", "to_id", "toId"))
    portnum = as_text(packet_field(payload, "portnum", "port_num"))

    conn.execute(
        """
        INSERT OR IGNORE INTO packets (
            packet_id, received_at, topic, packet_type, from_id, to_id, channel, portnum, payload_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            packet_id,
            now,
            topic,
            packet_type,
            from_id,
            to_id,
            channel,
            portnum,
            json.dumps(payload, separators=(",", ":"), ensure_ascii=True),
        ),
    )


def upsert_node(conn: sqlite3.Connection, topic: str, payload: dict[str, Any]) -> None:
    """Upsert latest node state from payload; preserve known fields when new values are null."""
    channel = infer_channel(topic)
    node = infer_node(payload, channel)
    if not node:
        return

    now = int(time.time())
    # last_seen should reflect when this collector last received any packet from the node.
    node["last_seen"] = now
    conn.execute(
        """
        INSERT INTO nodes (
            id, longname, shortname, role, channel, hw_model,
            last_lat, last_lon, last_seen, payload
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            longname=COALESCE(excluded.longname, nodes.longname),
            shortname=COALESCE(excluded.shortname, nodes.shortname),
            role=COALESCE(excluded.role, nodes.role),
            channel=COALESCE(excluded.channel, nodes.channel),
            hw_model=COALESCE(excluded.hw_model, nodes.hw_model),
            last_lat=COALESCE(excluded.last_lat, nodes.last_lat),
            last_lon=COALESCE(excluded.last_lon, nodes.last_lon),
            last_seen=excluded.last_seen,
            payload=excluded.payload
        """,
        (
            node["id"],
            node["longname"],
            node["shortname"],
            node["role"],
            node["channel"],
            node["hw_model"],
            node["last_lat"],
            node["last_lon"],
            node["last_seen"],
            json.dumps(payload, separators=(",", ":"), ensure_ascii=True),
        ),
    )


def decrypt_packet(packet: Any, key: bytes) -> bool:
    """Attempt Meshtastic AES-CTR packet decryption in-place."""
    if packet.HasField("decoded"):
        return True

    packet_id = packet.id.to_bytes(8, "little")
    from_node_id = getattr(packet, "from").to_bytes(8, "little")
    nonce = packet_id + from_node_id

    try:
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    except ValueError:
        # Invalid AES key size should not crash message handling.
        return False
    decryptor = cipher.decryptor()
    raw_proto = decryptor.update(packet.encrypted) + decryptor.finalize()

    try:
        data = Data()
        data.ParseFromString(raw_proto)
        packet.decoded.CopyFrom(data)
    except DecodeError:
        return False
    return True


def _decode_json(payload_bytes: bytes) -> dict[str, Any] | None:
    """Decode JSON payload bytes into dict."""
    try:
        payload = json.loads(payload_bytes.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _decode_meshtastic(
    payload_bytes: bytes,
    keyring: list[bytes],
    skip_node_ids: set[int],
) -> dict[str, Any] | None:
    """Decode Meshtastic ServiceEnvelope payload bytes into dict."""
    envelope = ServiceEnvelope()
    try:
        envelope.ParseFromString(payload_bytes)
    except DecodeError:
        return None

    packet = envelope.packet

    if not packet.HasField("decoded"):
        for key in keyring:
            if decrypt_packet(packet, key):
                break

    if not packet.HasField("decoded"):
        return None

    from_node_id = getattr(packet, "from", None)
    if from_node_id in skip_node_ids:
        return None

    payload = json_format.MessageToDict(envelope, preserving_proto_field_name=True)
    if not isinstance(payload, dict):
        return None

    packet_payload = payload.get("packet")
    if isinstance(packet_payload, dict):
        decoded = packet_payload.get("decoded")
        if isinstance(decoded, dict):
            payload.update(decoded)

    # Decode app payload bytes into structured dict for known app ports.
    # This makes fields human-readable and lets infer_node() consume nodeinfo/position.
    app_payload_dict: dict[str, Any] | None = None
    portnum = getattr(packet.decoded, "portnum", None)
    if packet.decoded.payload:
        try:
            if portnum == PortNum.NODEINFO_APP:
                msg = User()
                msg.ParseFromString(packet.decoded.payload)
                app_payload_dict = json_format.MessageToDict(
                    msg, preserving_proto_field_name=True
                )
                payload["type"] = "nodeinfo"
            elif portnum == PortNum.POSITION_APP:
                msg = Position()
                msg.ParseFromString(packet.decoded.payload)
                app_payload_dict = json_format.MessageToDict(
                    msg, preserving_proto_field_name=True
                )
                payload["type"] = "position"
            elif portnum == PortNum.TELEMETRY_APP:
                msg = Telemetry()
                msg.ParseFromString(packet.decoded.payload)
                app_payload_dict = json_format.MessageToDict(
                    msg, preserving_proto_field_name=True
                )
                payload["type"] = "telemetry"
            elif portnum == PortNum.TEXT_MESSAGE_APP:
                text = packet.decoded.payload.decode("utf-8", errors="replace")
                app_payload_dict = {"text": text}
                payload["type"] = "text"
        except DecodeError:
            app_payload_dict = None

    if isinstance(app_payload_dict, dict):
        payload["payload"] = app_payload_dict

    return payload


def decode_payload(settings: Settings, payload_bytes: bytes) -> dict[str, Any] | None:
    """Decode payload according to selected mode: json, meshtastic, or auto."""
    keyring = []
    if settings.primary_key is not None:
        keyring.append(settings.primary_key)

    if settings.payload_format == "json":
        return _decode_json(payload_bytes)

    if settings.payload_format == "meshtastic":
        return _decode_meshtastic(payload_bytes, keyring, settings.skip_node_ids)

    payload = _decode_json(payload_bytes)
    if payload is not None:
        return payload

    return _decode_meshtastic(payload_bytes, keyring, settings.skip_node_ids)


def purge_old_packets(conn: sqlite3.Connection, now: int, retention_days: int) -> int:
    """Delete packets older than retention window and return deleted row count."""
    cutoff = now - (retention_days * 24 * 60 * 60)
    cur = conn.execute("DELETE FROM packets WHERE received_at < ?", (cutoff,))
    return int(cur.rowcount or 0)


def next_daily_purge_epoch(now: int, hour_utc: int) -> int:
    """Compute next UTC epoch for daily purge at the given hour."""
    current = datetime.fromtimestamp(now, tz=timezone.utc)
    target = current.replace(hour=hour_utc, minute=0, second=0, microsecond=0)
    if target <= current:
        target += timedelta(days=1)
    return int(target.timestamp())


def on_connect(client: mqtt.Client, _userdata: Any, _flags: Any, rc: int, _props: Any = None) -> None:
    """MQTT connect callback: subscribe to configured topic on success."""
    settings: Settings = client._meshviewlite_settings  # type: ignore[attr-defined]
    if rc == 0:
        print(f"Connected to {settings.broker}:{settings.port} (client_id={settings.client_id})")
        result, mid = client.subscribe(settings.topic)
        if result == mqtt.MQTT_ERR_SUCCESS:
            print(f"Subscribe requested: topic='{settings.topic}' mid={mid}")
        else:
            print(f"Subscribe failed immediately: topic='{settings.topic}' rc={result}")
    else:
        print(f"Connection failed, rc={rc}")


def on_subscribe(
    client: mqtt.Client,
    _userdata: Any,
    mid: int,
    granted_qos: Any,
    _properties: Any = None,
) -> None:
    """MQTT subscribe callback: confirms broker accepted subscription."""
    settings: Settings = client._meshviewlite_settings  # type: ignore[attr-defined]
    print(f"Subscription acknowledged: topic='{settings.topic}' mid={mid} qos={granted_qos}")


def on_disconnect(
    client: mqtt.Client,
    _userdata: Any,
    rc: int,
    _properties: Any = None,
    _reason_code: Any = None,
) -> None:
    """MQTT disconnect callback: surface broker/network disconnect reasons."""
    if rc == 0:
        print("Disconnected from MQTT broker")
    else:
        print(f"Unexpected MQTT disconnect rc={rc}")


def on_log(client: mqtt.Client, _userdata: Any, level: int, buf: str) -> None:
    """Optional low-level MQTT protocol logs (enabled by --verbose-mqtt)."""
    settings: Settings = client._meshviewlite_settings  # type: ignore[attr-defined]
    if settings.verbose_mqtt:
        print(f"[mqtt:{level}] {buf}")


def on_message(client: mqtt.Client, _userdata: Any, msg: mqtt.MQTTMessage) -> None:
    """MQTT message callback: decode, retain, store packet, and upsert node."""
    conn: sqlite3.Connection = client._meshviewlite_db  # type: ignore[attr-defined]
    settings: Settings = client._meshviewlite_settings  # type: ignore[attr-defined]
    now = int(time.time())
    next_purge_at: int = client._meshviewlite_next_purge_at  # type: ignore[attr-defined]
    client._meshviewlite_rx_count += 1  # type: ignore[attr-defined]

    payload = decode_payload(settings, bytes(msg.payload))
    if not payload:
        client._meshviewlite_decode_fail_count += 1  # type: ignore[attr-defined]
        if settings.verbose_mqtt:
            print(
                f"RX undecodable topic='{msg.topic}' bytes={len(msg.payload)} "
                f"total_rx={client._meshviewlite_rx_count} "
                f"decode_fail={client._meshviewlite_decode_fail_count}"
            )
        return

    try:
        if now >= next_purge_at:
            deleted = purge_old_packets(conn, now, settings.retention_days)
            if deleted > 0:
                print(
                    f"Retention: deleted {deleted} packet(s) older than {settings.retention_days} days"
                )
            client._meshviewlite_next_purge_at = next_daily_purge_epoch(  # type: ignore[attr-defined]
                now, settings.purge_hour_utc
            )
        store_packet(conn, msg.topic, payload)
        upsert_node(conn, msg.topic, payload)
        if settings.log_packets:
            packet_id = packet_field(payload, "id")
            packet_type = infer_packet_type(payload) or "-"
            from_id = packet_field(payload, "from", "from_id", "fromId") or "-"
            to_id = packet_field(payload, "to", "to_id", "toId") or "-"
            channel = infer_channel(msg.topic) or "-"
            print(
                f"Packet id={packet_id} type={packet_type} from={from_id} "
                f"to={to_id} channel={channel} topic={msg.topic}"
            )
        if settings.log_decoded:
            packet_id = packet_field(payload, "id")
            print(f"Decoded packet topic='{msg.topic}' id={packet_id}")
            print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
        elif settings.verbose_mqtt and client._meshviewlite_rx_count % 100 == 0:  # type: ignore[attr-defined]
            print(
                f"RX summary total_rx={client._meshviewlite_rx_count} "  # type: ignore[attr-defined]
                f"decode_fail={client._meshviewlite_decode_fail_count}"  # type: ignore[attr-defined]
            )
        conn.commit()
    except Exception as exc:
        conn.rollback()
        print(f"Failed DB write for topic '{msg.topic}': {exc}", file=sys.stderr)


def main() -> int:
    """Program entrypoint."""
    settings = parse_args()
    conn = sqlite3.connect(str(settings.db_path))
    init_db(conn)
    print(f"Database: {settings.db_path}")

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=settings.client_id)
    client._meshviewlite_settings = settings  # type: ignore[attr-defined]
    client._meshviewlite_db = conn  # type: ignore[attr-defined]
    client._meshviewlite_next_purge_at = next_daily_purge_epoch(  # type: ignore[attr-defined]
        int(time.time()), settings.purge_hour_utc
    )
    client._meshviewlite_rx_count = 0  # type: ignore[attr-defined]
    client._meshviewlite_decode_fail_count = 0  # type: ignore[attr-defined]
    client.on_connect = on_connect
    client.on_subscribe = on_subscribe
    client.on_disconnect = on_disconnect
    client.on_log = on_log
    client.on_message = on_message

    if settings.username is not None or settings.password is not None:
        client.username_pw_set(settings.username or "", settings.password)
    if settings.tls:
        client.tls_set()
        if settings.insecure_tls:
            client.tls_insecure_set(True)

    def shutdown(_sig: int, _frame: Any) -> None:
        print("Shutting down...")
        try:
            client.disconnect()
        finally:
            conn.close()
            raise SystemExit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        client.connect(settings.broker, settings.port, settings.keepalive)
        client.loop_forever()
        return 0
    except socket.gaierror as exc:
        print(
            f"DNS lookup failed for broker '{settings.broker}'. "
            "Set [mqtt].broker in your config to a real hostname or IP address.",
            file=sys.stderr,
        )
        print(f"Original error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(
            f"Failed to connect to broker {settings.broker}:{settings.port}: {exc}",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
