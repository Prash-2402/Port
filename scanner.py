"""
scanner.py — Core port scanning logic for Port Scanner + Vulnerability Reporter
"""

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED

# ── Service Map ────────────────────────────────────────────────────────────────
SERVICE_MAP: dict[int, str] = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

# ── High-Risk Flags ──────────────────────────────────────────────────────────
HIGH_RISK: dict[int, str] = {
    21:   "FTP sends credentials in plaintext",
    23:   "Telnet is completely unencrypted",
    139:  "NetBIOS — common target for SMB attacks",
    445:  "SMB — EternalBlue / WannaCry exploit vector",
    3389: "RDP — brute force & BlueKeep vulnerability",
    5900: "VNC — often misconfigured with weak/no auth",
}


def resolve_target(target: str) -> str:
    """
    Resolve a hostname or IP string to a dotted-decimal IP address.
    Raises ValueError if resolution fails.
    """
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve '{target}': {exc}") from exc


def scan_port(ip: str, port: int, timeout: float = 0.5):
    """
    Attempt a TCP connect to (ip, port).
    Returns the port number if open, else None.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return port
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def scan_all_ports(
    ip: str,
    start: int,
    end: int,
    progress_callback=None,
    timeout: float = 0.5,
    max_workers: int = 200,
    deadline: float = 30.0,
) -> list[int]:
    """
    Scan ports [start, end] on ip using a thread pool.

    progress_callback(percent: int) is called at every 10% milestone.
    Raises TimeoutError if scanning exceeds deadline seconds.
    Returns a sorted list of open port numbers.
    """
    ports = list(range(start, end + 1))
    total = len(ports)
    open_ports: list[int] = []
    completed = 0
    next_milestone = 10
    start_time = time.monotonic()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, ip, p, timeout): p for p in ports}

        for future in as_completed(futures):
            # Check wall-clock deadline
            if time.monotonic() - start_time > deadline:
                executor.shutdown(wait=False, cancel_futures=True)
                raise TimeoutError("Scan exceeded 30-second limit.")

            result = future.result()
            if result is not None:
                open_ports.append(result)

            completed += 1
            pct = (completed / total) * 100
            if pct >= next_milestone:
                if progress_callback:
                    progress_callback(min(int(next_milestone), 100))
                next_milestone += 10

    return sorted(open_ports)


def build_report(ip: str, open_ports: list[int]) -> list[dict]:
    """
    Build a structured report for each open port.
    Returns a list of dicts: {port, service, risk_level, reason}
    """
    report = []
    for port in open_ports:
        service    = SERVICE_MAP.get(port, "Unknown")
        is_high    = port in HIGH_RISK
        risk_level = "HIGH" if is_high else "Low"
        reason     = HIGH_RISK.get(port, "—")
        report.append({
            "port":       port,
            "service":    service,
            "risk_level": risk_level,
            "reason":     reason,
        })
    # Sort: HIGH risk first, then by port number
    report.sort(key=lambda r: (0 if r["risk_level"] == "HIGH" else 1, r["port"]))
    return report
