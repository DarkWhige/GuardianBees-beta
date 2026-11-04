import pandas as pd


FEATURE_COLUMNS = [
    "window_start",
    "src_ip",
    "requests",
    "n_ports",
    "n_dst",
    "n_proto",
    "bytes",
    "syn_requests",
    "outgoing_requests",
    "local_requests",
    "n_dns_queries",
    "dns_queries",
]


def aggregate(packets, window="30s"):
    """Aggregate normalized packet records into analyzer-ready features."""
    if not packets:
        return pd.DataFrame(columns=FEATURE_COLUMNS)

    frame = pd.DataFrame.from_records(packets)
    required = {
        "ts",
        "src_ip",
        "dst_ip",
        "proto",
        "dport",
        "tcp_syn",
        "direction",
        "dns_query",
        "size",
    }
    missing = required.difference(frame.columns)
    if missing:
        raise ValueError(f"Missing packet fields: {', '.join(sorted(missing))}")

    frame["ts"] = pd.to_datetime(frame["ts"], unit="s", utc=True)
    frame["dport"] = pd.to_numeric(frame["dport"], errors="coerce")
    frame["size"] = pd.to_numeric(frame["size"], errors="raise")
    frame["tcp_syn"] = frame["tcp_syn"].astype(bool)
    frame["is_outgoing"] = frame["direction"].eq("sortant")
    frame["is_local"] = frame["direction"].eq("local")

    features = (
        frame.groupby(
            [
                pd.Grouper(key="ts", freq=window),
                "src_ip",
            ],
            dropna=False,
        )
        .agg(
            requests=("dport", "size"),
            n_ports=("dport", "nunique"),
            n_dst=("dst_ip", "nunique"),
            n_proto=("proto", "nunique"),
            bytes=("size", "sum"),
            syn_requests=("tcp_syn", "sum"),
            outgoing_requests=("is_outgoing", "sum"),
            local_requests=("is_local", "sum"),
            n_dns_queries=("dns_query", lambda values: values.dropna().nunique()),
            dns_queries=(
                "dns_query",
                lambda values: ", ".join(sorted(set(values.dropna()))),
            ),
        )
        .reset_index()
        .rename(columns={"ts": "window_start"})
    )
    return features[FEATURE_COLUMNS]
