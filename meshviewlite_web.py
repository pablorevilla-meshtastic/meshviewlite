#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import mimetypes
import re
import sqlite3
import tomllib
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from jinja2 import Environment, FileSystemLoader, TemplateNotFound, select_autoescape
from meshtastic.protobuf.config_pb2 import Config
from meshtastic.protobuf.mesh_pb2 import HardwareModel
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlparse

APP_VERSION = "lite 1.0.0"


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


PORTNUM_ALIASES: dict[int, tuple[str, ...]] = {
    1: ("text",),
    3: ("position", "location"),
    4: ("nodeinfo", "node info"),
    67: ("telemetry",),
    71: ("neighbor", "neighbors"),
}


def load_config(config_path: Path | None) -> dict[str, Any]:
    if config_path is None:
        return {}
    with config_path.open("rb") as fh:
        loaded = tomllib.load(fh)
    if not isinstance(loaded, dict):
        raise ValueError("Config file must contain a TOML table at top level")
    return loaded


def get_config_value(config: dict[str, Any], section: str, key: str, default: Any) -> Any:
    section_data = config.get(section)
    if isinstance(section_data, dict) and key in section_data:
        return section_data[key]
    return default


def parse_args() -> argparse.Namespace:
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--config", default=None)
    pre_args, _ = pre.parse_known_args()

    config: dict[str, Any] = {}
    config_path = Path(pre_args.config) if pre_args.config else None
    if config_path:
        config = load_config(config_path)

    parser = argparse.ArgumentParser(description="meshviewlite web UI")
    parser.add_argument("--config", default=pre_args.config, help="TOML config path")
    parser.add_argument(
        "--db",
        default=get_config_value(config, "mqtt", "db", "meshviewlite.db"),
        help="SQLite DB path",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind host")
    parser.add_argument("--port", type=int, default=8050, help="Bind port")
    return parser.parse_args()


def app_title_from_db_path(db_path: Path) -> str:
    stem = db_path.stem.strip()
    if not stem:
        return "Meshview Lite"
    clean = re.sub(r"[_\-]+", " ", stem)
    words = [w.capitalize() for w in clean.split() if w]
    prefix = " ".join(words) if words else "Meshview"
    return f"{prefix} Meshview Lite"


def format_ts(epoch: int | None) -> str:
    if epoch is None:
        return "-"
    try:
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (TypeError, ValueError, OSError):
        return "-"


def pretty_payload(raw_json: str) -> str:
    try:
        data = json.loads(raw_json)
        return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False)
    except json.JSONDecodeError:
        return raw_json


def portnum_label(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, (int, float)):
        return PORTNUM_NAMES.get(int(value), str(int(value)))
    text = str(value).strip()
    if not text:
        return "-"
    try:
        return PORTNUM_NAMES.get(int(text, 10), text)
    except ValueError:
        return text


def normalize_packet_type(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip().lower()
    for ch in (" ", "_", "&", "+", "-", "(", ")"):
        text = text.replace(ch, "")
    return text


def payload_to_textproto(value: Any, indent: int = 0) -> str:
    pad = "  " * indent
    lines: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, dict):
                lines.append(f"{pad}{key} {{")
                lines.append(payload_to_textproto(item, indent + 1))
                lines.append(f"{pad}}}")
            elif isinstance(item, list):
                for elem in item:
                    if isinstance(elem, dict):
                        lines.append(f"{pad}{key} {{")
                        lines.append(payload_to_textproto(elem, indent + 1))
                        lines.append(f"{pad}}}")
                    else:
                        lines.append(f"{pad}{key}: {elem}")
            elif isinstance(item, str):
                lines.append(f'{pad}{key}: "{item}"')
            elif item is True:
                lines.append(f"{pad}{key}: true")
            elif item is False:
                lines.append(f"{pad}{key}: false")
            elif item is None:
                continue
            else:
                lines.append(f"{pad}{key}: {item}")
    else:
        lines.append(f"{pad}{value}")
    return "\n".join(lines)


def payload_json_to_text(raw_json: str) -> str:
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        return raw_json
    return payload_to_textproto(data)


def extract_profile_from_payload(raw_json: str) -> dict[str, Any]:
    try:
        payload = json.loads(raw_json)
    except json.JSONDecodeError:
        return {}
    if not isinstance(payload, dict):
        return {}

    user = payload.get("user") if isinstance(payload.get("user"), dict) else {}
    position = payload.get("position") if isinstance(payload.get("position"), dict) else {}
    nested_payload = payload.get("payload") if isinstance(payload.get("payload"), dict) else {}

    def _enum_name(enum_type: Any, value: Any) -> str | None:
        if isinstance(value, (int, float)):
            try:
                return enum_type.Name(int(value))
            except Exception:
                return str(int(value))
        if isinstance(value, str):
            stripped = value.strip()
            return stripped or None
        return None

    long_name = (
        payload.get("long_name")
        or user.get("longName")
        or user.get("long_name")
        or nested_payload.get("longname")
        or nested_payload.get("long_name")
    )
    short_name = (
        payload.get("short_name")
        or user.get("shortName")
        or user.get("short_name")
        or nested_payload.get("shortname")
        or nested_payload.get("short_name")
    )
    hw_model = _enum_name(
        HardwareModel,
        payload.get("hw_model")
        or user.get("hwModel")
        or user.get("hw_model")
        or nested_payload.get("hw_model")
        or nested_payload.get("hardware"),
    )
    role = _enum_name(
        Config.DeviceConfig.Role,
        payload.get("role") or user.get("role") or nested_payload.get("role"),
    )
    channel_raw = payload.get("channel")
    channel: str | None
    if isinstance(channel_raw, str):
        stripped = channel_raw.strip()
        if stripped and re.fullmatch(r"![0-9a-fA-F]{8}", stripped) is None and stripped != "0":
            channel = stripped
        else:
            channel = None
    else:
        channel = None

    lat = payload.get(
        "last_lat",
        payload.get(
            "lat",
            position.get("latitude", nested_payload.get("latitude_i", nested_payload.get("latitude"))),
        ),
    )
    lon = payload.get(
        "last_long",
        payload.get(
            "lon",
            position.get("longitude", nested_payload.get("longitude_i", nested_payload.get("longitude"))),
        ),
    )
    lat_i32 = MeshViewHandler._to_i32_coord(lat)
    lon_i32 = MeshViewHandler._to_i32_coord(lon)

    return {
        "long_name": long_name,
        "short_name": short_name,
        "hw_model": hw_model,
        "role": role,
        "channel": channel,
        "last_lat": lat_i32,
        "last_long": lon_i32,
    }


TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
STATIC_ROOT = Path(__file__).resolve().parent
JINJA = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape(enabled_extensions=("html", "xml"), default=True),
)


class MeshViewHandler(BaseHTTPRequestHandler):
    server: "MeshViewServer"

    def _db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.server.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _send_html(self, status: int, content: str) -> None:
        encoded = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _render_template(self, template_name: str, **context: Any) -> str:
        try:
            template = JINJA.get_template(template_name)
        except TemplateNotFound:
            return "<h1>Template not found</h1>"
        context.setdefault("title", self.server.app_title)
        context.setdefault("app_title", self.server.app_title)
        return template.render(**context)

    def _send_not_found(self, message: str = "Not found") -> None:
        body = self._render_template("not_found.html", message=message)
        self._send_html(404, body)

    def _send_bytes(self, status: int, content_type: str, payload: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _handle_static(self, parsed: Any) -> None:
        rel = parsed.path[len("/static/") :]
        if rel != "portmaps.js":
            self._send_not_found()
            return
        candidate = (STATIC_ROOT / rel).resolve()
        if not candidate.is_file():
            self._send_not_found()
            return
        payload = candidate.read_bytes()
        mime, _ = mimetypes.guess_type(str(candidate))
        self._send_bytes(200, mime or "application/octet-stream", payload)

    @staticmethod
    def _node_id_to_pair(node_id_value: Any) -> tuple[str, int | None]:
        text = str(node_id_value) if node_id_value is not None else ""
        text = text.strip()
        if not text:
            return "", None
        if text.startswith("!"):
            try:
                return text.lower(), int(text[1:], 16)
            except ValueError:
                return text.lower(), None
        try:
            numeric = int(text, 10)
            return f"!{numeric:08x}", numeric
        except ValueError:
            return text.lower(), None

    @staticmethod
    def _to_i32_coord(value: Any) -> int | None:
        if value is None:
            return None
        if isinstance(value, (int, float)):
            # Store API coordinates in 1e-7 degrees style integers.
            if abs(float(value)) <= 180.0:
                return int(round(float(value) * 10_000_000))
            return int(round(float(value)))
        return None

    @staticmethod
    def _coord_to_deg(value: Any) -> float | None:
        if value is None:
            return None
        try:
            num = float(value)
        except (TypeError, ValueError):
            return None
        if abs(num) > 180:
            return num / 10_000_000.0
        return num

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path.startswith("/static/"):
            self._handle_static(parsed)
            return
        if parsed.path in ("/api/nodes", "/api/node"):
            self._handle_api_nodes()
            return
        if parsed.path in ("/api/version", "/version"):
            self._send_json(200, {"version": APP_VERSION})
            return
        if parsed.path == "/api/packets":
            self._handle_api_packets(parsed)
            return
        if parsed.path == "/":
            self._handle_index(parsed)
            return
        if parsed.path == "/packets":
            self._handle_packets_page()
            return
        if parsed.path == "/map":
            self._handle_map()
            return
        if parsed.path in ("/chat", "/ch"):
            self._handle_chat()
            return
        if parsed.path == "/about":
            self._handle_about()
            return
        if parsed.path.startswith("/node/"):
            node_id = unquote(parsed.path[len("/node/") :])
            if node_id:
                self._handle_node(node_id)
                return
        self._send_not_found()

    def _handle_index(self, parsed: Any) -> None:
        query = parse_qs(parsed.query)
        q = (query.get("q", [""])[0] or "").strip()

        sql = """
            SELECT id AS node_id, longname AS long_name, shortname AS short_name, hw_model, role, channel,
                   last_lat, last_lon, last_seen
            FROM nodes
        """
        params: list[Any] = []
        if q:
            sql += " WHERE CAST(id AS TEXT) LIKE ? OR longname LIKE ? OR shortname LIKE ?"
            pattern = f"%{q}%"
            params.extend([pattern, pattern, pattern])
        sql += " ORDER BY last_seen DESC LIMIT 500"

        with self._db() as conn:
            nodes = conn.execute(sql, params).fetchall()

        rows: list[dict[str, Any]] = []
        for n in nodes:
            node_id_text = str(n["node_id"])
            node_href = quote(node_id_text, safe="")
            rows.append(
                {
                    "node_id": node_id_text,
                    "node_href": node_href,
                    "name": n["long_name"] or n["short_name"] or "-",
                    "hw_model": n["hw_model"] or "-",
                    "role": n["role"] or "-",
                    "channel": n["channel"] or "-",
                    "last_seen_epoch": int(n["last_seen"]) if n["last_seen"] is not None else None,
                }
            )

        body = self._render_template("index.html", q=q, nodes=rows)
        self._send_html(200, body)

    def _handle_map(self) -> None:
        body = self._render_template("map.html")
        self._send_html(200, body)

    def _handle_packets_page(self) -> None:
        body = self._render_template("packets.html")
        self._send_html(200, body)

    def _handle_chat(self) -> None:
        body = self._render_template("chat.html")
        self._send_html(200, body)

    def _handle_about(self) -> None:
        body = self._render_template("about.html")
        self._send_html(200, body)

    def _handle_api_nodes(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        node_id_filter_raw = (query.get("node_id", [""])[0] or "").strip()
        include_sparse = (query.get("include_sparse", ["0"])[0] or "0").strip() in (
            "1",
            "true",
            "yes",
            "on",
        )
        node_id_filter_value: str | None = None
        if node_id_filter_raw:
            try:
                node_id_filter_value = str(int(node_id_filter_raw, 10))
            except ValueError:
                self._send_json(200, {"nodes": []})
                return

        with self._db() as conn:
            packet_nodes = conn.execute(
                """
                SELECT p.from_id AS node_id,
                       MIN(p.received_at) AS first_seen,
                       MAX(p.received_at) AS last_seen
                FROM packets p
                WHERE p.from_id IS NOT NULL
                  AND p.packet_type IS NOT NULL
                  AND lower(replace(replace(replace(replace(p.packet_type, '_', ''), ' ', ''), '(', ''), ')', ''))
                      IN ('nodeinfo', 'telemetry', 'position', 'location', 'text', 'routing', 'traceroute', 'neighbor')
                GROUP BY p.from_id
                ORDER BY last_seen DESC
                """
            ).fetchall()

            nodes_rows = conn.execute(
                """
                SELECT id, longname AS long_name, shortname AS short_name, hw_model, role, last_lat, last_lon, channel, last_seen
                FROM nodes
                """
            ).fetchall()
            nodes_by_id = {str(r["id"]): r for r in nodes_rows}
            latest_packet_rows = conn.execute(
                """
                SELECT p.from_id, p.payload_json
                FROM packets p
                JOIN (
                    SELECT from_id, MAX(received_at) AS max_seen
                    FROM packets
                    WHERE from_id IS NOT NULL
                      AND packet_type IS NOT NULL
                      AND lower(replace(replace(replace(replace(packet_type, '_', ''), ' ', ''), '(', ''), ')', ''))
                          IN ('nodeinfo', 'telemetry', 'position', 'location', 'text', 'routing', 'traceroute', 'neighbor')
                    GROUP BY from_id
                ) t ON t.from_id = p.from_id AND t.max_seen = p.received_at
                WHERE p.from_id IS NOT NULL
                  AND p.packet_type IS NOT NULL
                  AND lower(replace(replace(replace(replace(p.packet_type, '_', ''), ' ', ''), '(', ''), ')', ''))
                      IN ('nodeinfo', 'telemetry', 'position', 'location', 'text', 'routing', 'traceroute', 'neighbor')
                """
            ).fetchall()
            latest_payload_by_from: dict[str, str] = {}
            for r in latest_packet_rows:
                key = str(r["from_id"])
                if key not in latest_payload_by_from:
                    latest_payload_by_from[key] = r["payload_json"]

        nodes: list[dict[str, Any]] = []
        for row in packet_nodes:
            node_id_key = str(row["node_id"])
            if node_id_filter_value is not None and node_id_key != node_id_filter_value:
                continue
            node_id_text, node_id_num = self._node_id_to_pair(node_id_key)
            if node_id_num is None:
                continue

            latest_payload = latest_payload_by_from.get(node_id_key)
            profile_from_packet = extract_profile_from_payload(latest_payload) if latest_payload else {}
            node_row = nodes_by_id.get(node_id_key)
            last_seen_us = int(row["last_seen"]) * 1_000_000 if row["last_seen"] is not None else None
            first_seen_us = int(row["first_seen"]) * 1_000_000 if row["first_seen"] is not None else None

            long_name = (
                (node_row["long_name"] if node_row else None)
                or profile_from_packet.get("long_name")
            )
            short_name = (
                (node_row["short_name"] if node_row else None)
                or profile_from_packet.get("short_name")
            )
            hw_model = (
                (node_row["hw_model"] if node_row else None)
                or profile_from_packet.get("hw_model")
            )
            role = (
                (node_row["role"] if node_row else None)
                or profile_from_packet.get("role")
            )
            last_lat = (
                self._to_i32_coord(node_row["last_lat"]) if node_row else None
            ) or profile_from_packet.get("last_lat")
            last_long = (
                self._to_i32_coord(node_row["last_lon"]) if node_row else None
            ) or profile_from_packet.get("last_long")
            channel = (
                (node_row["channel"] if node_row else None)
                or profile_from_packet.get("channel")
            )
            if isinstance(channel, str):
                channel = channel.strip() or None
            else:
                channel = None

            meaningful_channel = isinstance(channel, str) and channel not in ("0",)
            has_profile = any(
                value is not None
                for value in (long_name, short_name, hw_model, role, last_lat, last_long)
            )
            if not include_sparse and not (has_profile or meaningful_channel):
                continue

            nodes.append(
                {
                    "id": node_id_text or None,
                    "node_id": node_id_num,
                    "long_name": long_name,
                    "short_name": short_name,
                    "hw_model": hw_model,
                    "firmware": None,
                    "role": role,
                    "last_lat": last_lat,
                    "last_long": last_long,
                    "channel": channel,
                    "is_mqtt_gateway": None,
                    "first_seen_us": first_seen_us,
                    "last_seen_us": last_seen_us,
                }
            )

        self._send_json(200, {"nodes": nodes})

    def _handle_api_packets(self, parsed: Any) -> None:
        query = parse_qs(parsed.query)
        node_id = (query.get("node_id", [""])[0] or "").strip()
        from_node_id = (query.get("from_node_id", [""])[0] or "").strip()
        portnum_raw = (query.get("portnum", [""])[0] or "").strip()
        since_raw = (query.get("since", [""])[0] or "").strip()
        limit_raw = (query.get("limit", [""])[0] or "").strip()

        try:
            limit = int(limit_raw) if limit_raw else 200
        except ValueError:
            limit = 200
        limit = min(max(limit, 1), 50)

        where: list[str] = []
        params: list[Any] = []

        if node_id:
            where.append("(p.from_id = ? OR p.to_id = ?)")
            params.extend([node_id, node_id])

        if from_node_id:
            where.append("p.from_id = ?")
            params.append(from_node_id)

        if since_raw:
            try:
                since_num = int(float(since_raw))
                # UI commonly sends microseconds. Convert to seconds for DB comparison.
                since_sec = since_num // 1_000_000 if since_num > 10_000_000_000 else since_num
                where.append("p.received_at >= ?")
                params.append(since_sec)
            except ValueError:
                pass

        if portnum_raw:
            aliases: tuple[str, ...] = ()
            try:
                portnum_int = int(portnum_raw)
                aliases = PORTNUM_ALIASES.get(portnum_int, ())
                clauses = ["CAST(p.portnum AS INTEGER) = ?"]
                params.append(portnum_int)
                if aliases:
                    norm_packet_type_sql = (
                        "lower(replace(replace(replace(replace(replace(replace(p.packet_type,' ',''),'_',''),'&',''),'+',''),'-',''),'(',''))"
                    )
                    alias_clauses: list[str] = []
                    for alias in aliases:
                        alias_clauses.append(f"{norm_packet_type_sql} = ?")
                        params.append(normalize_packet_type(alias))
                    clauses.append("(" + " OR ".join(alias_clauses) + ")")
                where.append("(" + " OR ".join(clauses) + ")")
            except ValueError:
                pass

        where_sql = ("WHERE " + " AND ".join(where)) if where else ""

        sql = f"""
            SELECT p.id AS db_id, p.packet_id, p.received_at, p.topic, p.packet_type, p.from_id, p.to_id, p.channel, p.portnum, p.payload_json,
                   nf.longname AS from_long_name, nf.shortname AS from_short_name,
                   nt.longname AS to_long_name, nt.shortname AS to_short_name
            FROM packets p
            LEFT JOIN nodes nf ON CAST(nf.id AS TEXT) = p.from_id
            LEFT JOIN nodes nt ON CAST(nt.id AS TEXT) = p.to_id
            {where_sql}
            ORDER BY p.received_at DESC, p.id DESC
            LIMIT ?
        """
        params.append(limit)

        with self._db() as conn:
            rows = conn.execute(sql, params).fetchall()

        packets: list[dict[str, Any]] = []
        for row in rows:
            try:
                portnum_int = int(row["portnum"]) if row["portnum"] is not None else None
            except ValueError:
                portnum_int = None

            if portnum_int is None:
                norm = normalize_packet_type(row["packet_type"])
                for pnum, aliases in PORTNUM_ALIASES.items():
                    if norm in {normalize_packet_type(a) for a in aliases}:
                        portnum_int = pnum
                        break

            import_time_us = int(row["received_at"]) * 1_000_000 if row["received_at"] is not None else None

            packets.append(
                {
                    "id": row["packet_id"],
                    "import_time_us": import_time_us,
                    "topic": row["topic"],
                    "packet_type": row["packet_type"],
                    "from_node_id": int(row["from_id"]) if row["from_id"] and str(row["from_id"]).isdigit() else row["from_id"],
                    "to_node_id": int(row["to_id"]) if row["to_id"] and str(row["to_id"]).isdigit() else row["to_id"],
                    "from_long_name": row["from_long_name"],
                    "to_long_name": row["to_long_name"] or row["to_short_name"],
                    "long_name": row["from_long_name"] or row["from_short_name"],
                    "portnum": portnum_int,
                    "channel": row["channel"],
                    "payload": payload_json_to_text(row["payload_json"]),
                }
            )

        self._send_json(200, {"packets": packets})

    def _handle_node(self, node_id: str) -> None:
        candidate_ids: list[str] = []
        raw = node_id.strip()
        if raw:
            candidate_ids.append(raw)
        if raw.startswith("!"):
            try:
                candidate_ids.append(str(int(raw[1:], 16)))
            except ValueError:
                pass
        else:
            try:
                numeric = int(raw, 10)
                candidate_ids.append(str(numeric))
                candidate_ids.append(f"!{numeric:08x}")
            except ValueError:
                pass
        candidate_ids = list(dict.fromkeys(candidate_ids))
        if not candidate_ids:
            self._send_not_found(f"Node not found: {node_id}")
            return

        placeholders = ",".join("?" for _ in candidate_ids)

        with self._db() as conn:
            node = conn.execute(
                f"""
                SELECT id AS node_id, longname AS long_name, shortname AS short_name, hw_model, role, channel,
                       last_lat, last_lon, last_seen, payload AS raw_json
                FROM nodes
                WHERE CAST(id AS TEXT) IN ({placeholders})
                ORDER BY last_seen DESC
                LIMIT 1
                """,
                candidate_ids,
            ).fetchone()
            if node is None:
                self._send_not_found(f"Node not found: {node_id}")
                return

            node_id_text = str(node["node_id"])
            packets = conn.execute(
                """
                SELECT id, packet_id, received_at, topic, packet_type, from_id, to_id, channel, portnum, payload_json
                FROM packets
                WHERE from_id = ? OR to_id = ?
                ORDER BY received_at DESC
                LIMIT 200
                """,
                (node_id_text, node_id_text),
            ).fetchall()

        packet_rows: list[dict[str, Any]] = []
        for p in packets:
            packet_rows.append(
                {
                    "id": p["packet_id"],
                    "packet_id": p["packet_id"],
                    "db_id": p["id"],
                    "time": format_ts(p["received_at"]),
                    "packet_type": p["packet_type"],
                    "from_id": p["from_id"],
                    "to_id": p["to_id"],
                    "channel": p["channel"],
                    "port_label": portnum_label(p["portnum"]),
                    "topic": p["topic"],
                    "payload": pretty_payload(p["payload_json"]),
                }
            )

        lat_deg = self._coord_to_deg(node["last_lat"])
        lon_deg = self._coord_to_deg(node["last_lon"])
        show_map = lat_deg is not None and lon_deg is not None

        node_data = {
            "id": node_id_text,
            "node_id_int": int(node_id_text) if node_id_text.isdigit() else None,
            "display_name": node["long_name"] or node["short_name"] or "Unnamed node",
            "shortname": node["short_name"],
            "hw_model": node["hw_model"],
            "role": node["role"],
            "channel": node["channel"],
            "last_seen_fmt": format_ts(node["last_seen"]),
            "lat_display": f"{lat_deg:.6f}" if lat_deg is not None else "-",
            "lon_display": f"{lon_deg:.6f}" if lon_deg is not None else "-",
            "lat_deg": lat_deg,
            "lon_deg": lon_deg,
        }

        body = self._render_template(
            "node.html",
            node=node_data,
            show_map=show_map,
            packets=packet_rows,
        )
        self._send_html(200, body)


class MeshViewServer(ThreadingHTTPServer):
    def __init__(self, server_address: tuple[str, int], db_path: Path):
        super().__init__(server_address, MeshViewHandler)
        self.db_path = db_path
        self.app_title = app_title_from_db_path(db_path)


def main() -> int:
    args = parse_args()
    db_path = Path(args.db)
    if not db_path.exists():
        raise SystemExit(f"Database file not found: {db_path}")

    server = MeshViewServer((args.host, args.port), db_path)
    print(
        f"Serving {server.app_title} at http://{args.host}:{args.port}/ (db: {db_path})"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
