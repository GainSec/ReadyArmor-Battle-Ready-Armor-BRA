"""Host environment collection for engagement startup context."""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
from typing import Any


def _which(name: str) -> str | None:
    """Return the executable path if available."""
    return shutil.which(name)


def _run_command(cmd: list[str], timeout_s: float = 0.8) -> str:
    """Run a command and return stripped stdout, or empty string on failure."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        if result.returncode != 0:
            return ""
        return (result.stdout or "").strip()
    except Exception:
        return ""


def _parse_interfaces_from_ip_link(output: str) -> list[str]:
    interfaces: list[str] = []
    for line in output.splitlines():
        match = re.match(r"^\d+:\s+([^:]+):", line.strip())
        if not match:
            continue
        iface = match.group(1).split("@", 1)[0]
        if iface.startswith("lo"):
            continue
        if iface and iface not in interfaces:
            interfaces.append(iface)
    return interfaces


def _parse_ipv4_from_ip_addr(output: str) -> list[str]:
    ips: list[str] = []
    for line in output.splitlines():
        match = re.match(r"^\d+:\s+([^ ]+)\s+inet\s+([0-9.]+(?:/[0-9]+)?)", line.strip())
        if not match:
            continue
        iface = match.group(1).split("@", 1)[0]
        ip = match.group(2)
        if ip.startswith("127."):
            continue
        item = f"{iface}={ip}"
        if item not in ips:
            ips.append(item)
    return ips


def _parse_interfaces_from_ifconfig(output: str) -> list[str]:
    interfaces: list[str] = []
    for line in output.splitlines():
        match = re.match(r"^([0-9A-Za-z._:-]+):", line)
        if not match:
            continue
        iface = match.group(1)
        if iface.startswith("lo"):
            continue
        if iface and iface not in interfaces:
            interfaces.append(iface)
    return interfaces


def _parse_ipv4_from_ifconfig(output: str) -> list[str]:
    ips: list[str] = []
    current_iface = ""
    for line in output.splitlines():
        iface_match = re.match(r"^([0-9A-Za-z._:-]+):", line)
        if iface_match:
            current_iface = iface_match.group(1)
            continue
        inet_match = re.search(r"\binet\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\b", line)
        if not inet_match:
            continue
        ip = inet_match.group(1)
        if ip.startswith("127.") or not current_iface or current_iface.startswith("lo"):
            continue
        item = f"{current_iface}={ip}"
        if item not in ips:
            ips.append(item)
    return ips


def _parse_link_status_from_ifconfig(output: str) -> dict[str, str]:
    """Parse interface link status values from ifconfig output."""
    statuses: dict[str, str] = {}
    current_iface = ""
    for line in output.splitlines():
        iface_match = re.match(r"^([0-9A-Za-z._:-]+):", line)
        if iface_match:
            current_iface = iface_match.group(1)
            continue
        status_match = re.search(r"\bstatus:\s+(\S+)", line.strip())
        if status_match and current_iface:
            statuses[current_iface] = status_match.group(1).lower()
    return statuses


def _parse_networksetup_hardware_ports(output: str) -> dict[str, str]:
    """Parse macOS networksetup hardware ports into iface -> hardware port label."""
    mapping: dict[str, str] = {}
    current_port = ""
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("Hardware Port:"):
            current_port = line.split(":", 1)[1].strip()
            continue
        if line.startswith("Device:"):
            iface = line.split(":", 1)[1].strip()
            if iface:
                mapping[iface] = current_port or "unknown"
    return mapping


def _classify_interface(iface: str, system_name: str, mac_ports: dict[str, str]) -> str:
    """Classify an interface for clearer routing hints in prompts."""
    low_iface = iface.lower()
    if low_iface.startswith("lo"):
        return "loopback"

    if system_name == "Darwin":
        port_label = str(mac_ports.get(iface, "")).lower()
        if any(token in port_label for token in ("wi-fi", "wifi", "wlan", "airport")):
            return "wireless"
        if any(token in port_label for token in ("ethernet", "lan")):
            return "ethernet"
        if "bridge" in port_label:
            return "virtual"

    if low_iface.startswith(("wl", "wlan", "wlp", "wlo", "ath")):
        return "wireless"
    if low_iface.startswith(("eth", "enp", "eno", "ens", "enx")):
        return "ethernet"
    if low_iface.startswith(("utun", "tun", "tap", "wg", "tailscale", "docker", "veth", "br-", "virbr", "vmnet")):
        return "virtual"
    return "unknown"


def _default_ipv4_for_interface(default_interface: str, ipv4_addresses: list[str]) -> str:
    """Return IPv4 assigned to default interface when available."""
    for item in ipv4_addresses:
        if "=" not in item:
            continue
        iface, ip = item.split("=", 1)
        if iface == default_interface and ip:
            return ip
    return ""


def _default_iface_from_route(system_name: str) -> str:
    if system_name == "Darwin" and _which("route"):
        output = _run_command(["route", "-n", "get", "default"])
        match = re.search(r"interface:\s+(\S+)", output)
        if match:
            return match.group(1)

    if _which("ip"):
        output = _run_command(["ip", "route", "show", "default"])
        match = re.search(r"\bdev\s+(\S+)", output)
        if match:
            return match.group(1)
    return "unknown"


def _default_gateway_from_route(system_name: str) -> str:
    """Resolve default gateway IP/hostname from system route output."""
    if system_name == "Darwin" and _which("route"):
        output = _run_command(["route", "-n", "get", "default"])
        match = re.search(r"gateway:\s+(\S+)", output)
        if match:
            return match.group(1)

    if _which("ip"):
        output = _run_command(["ip", "route", "show", "default"])
        match = re.search(r"\bvia\s+(\S+)", output)
        if match:
            return match.group(1)
    return "unknown"


def _parse_ipconfig_summary(output: str) -> dict[str, str]:
    """Parse simple key/value lines from macOS ipconfig getsummary output."""
    parsed: dict[str, str] = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key:
            parsed[key] = value
    return parsed


def _wifi_association_for_interface(system_name: str, iface: str) -> str:
    """Return Wi-Fi SSID for interface when available, else status marker."""
    if not iface:
        return "unknown"
    if system_name == "Darwin" and _which("networksetup"):
        fallback_state = "unknown"
        output = _run_command(["networksetup", "-getairportnetwork", iface], timeout_s=1.5)
        if output:
            lower = output.lower()
            if "not associated" in lower:
                fallback_state = "(disconnected)"
            elif ":" in output:
                ssid = output.split(":", 1)[1].strip()
                if ssid:
                    return ssid
            else:
                cleaned = output.strip()
                if cleaned:
                    return cleaned

        if _which("ipconfig"):
            summary = _run_command(["ipconfig", "getsummary", iface], timeout_s=1.5)
            if summary:
                fields = _parse_ipconfig_summary(summary)
                if fields.get("InterfaceType", "").strip().lower() == "wifi":
                    link_active = fields.get("LinkStatusActive", "").strip().upper() == "TRUE"
                    ssid = fields.get("SSID", "").strip()
                    if link_active:
                        if ssid and ssid.lower() not in {"<redacted>", "unknown"}:
                            return ssid
                        return "(associated)"
                    if not link_active and fallback_state == "unknown":
                        return "(disconnected)"

        return fallback_state
    return "unknown"


def _detect_os_label(system_name: str, kernel_release: str) -> str:
    if system_name == "Darwin":
        product_version = _run_command(["sw_vers", "-productVersion"])
        if product_version:
            return f"macOS {product_version}"
        return f"Darwin {kernel_release}".strip()

    if system_name == "Linux":
        try:
            with open("/etc/os-release", "r", encoding="utf-8") as handle:
                for line in handle:
                    if line.startswith("PRETTY_NAME="):
                        value = line.split("=", 1)[1].strip().strip('"')
                        if value:
                            return value
        except Exception:
            pass
        return f"Linux {kernel_release}".strip()

    if system_name:
        return f"{system_name} {kernel_release}".strip()
    return "Unknown"


def collect_host_profile() -> dict[str, Any]:
    """Collect lightweight host facts for LLM startup context."""
    system_name = platform.system()
    kernel_release = platform.release()

    interfaces: list[str] = []
    ipv4_addresses: list[str] = []
    network_source = "none"
    link_statuses: dict[str, str] = {}

    if _which("ip"):
        network_source = "ip"
        interfaces = _parse_interfaces_from_ip_link(_run_command(["ip", "-o", "link", "show"]))
        ipv4_addresses = _parse_ipv4_from_ip_addr(_run_command(["ip", "-o", "-4", "addr", "show", "scope", "global"]))
    elif _which("ifconfig"):
        network_source = "ifconfig"
        ifconfig_output = _run_command(["ifconfig", "-a"])
        interfaces = _parse_interfaces_from_ifconfig(ifconfig_output)
        ipv4_addresses = _parse_ipv4_from_ifconfig(ifconfig_output)
        link_statuses = _parse_link_status_from_ifconfig(ifconfig_output)

    default_interface = _default_iface_from_route(system_name)
    if default_interface == "unknown" and interfaces:
        default_interface = interfaces[0]
    default_gateway = _default_gateway_from_route(system_name)

    mac_ports: dict[str, str] = {}
    if system_name == "Darwin" and _which("networksetup"):
        mac_ports = _parse_networksetup_hardware_ports(
            _run_command(["networksetup", "-listallhardwareports"], timeout_s=1.5)
        )

    all_interfaces = list(interfaces)
    for item in ipv4_addresses:
        if "=" not in item:
            continue
        iface = item.split("=", 1)[0]
        if iface and iface not in all_interfaces:
            all_interfaces.append(iface)

    interface_types = {
        iface: _classify_interface(iface, system_name, mac_ports)
        for iface in all_interfaces
    }
    wifi_interfaces = [iface for iface, kind in interface_types.items() if kind == "wireless"]
    ethernet_interfaces = [iface for iface, kind in interface_types.items() if kind == "ethernet"]
    virtual_interfaces = [iface for iface, kind in interface_types.items() if kind == "virtual"]
    default_interface_type = interface_types.get(default_interface, "unknown")
    default_ipv4 = _default_ipv4_for_interface(default_interface, ipv4_addresses)
    virtual_interface_set = set(virtual_interfaces)
    virtual_ipv4_addresses = [
        item for item in ipv4_addresses
        if "=" in item and item.split("=", 1)[0] in virtual_interface_set
    ]
    ipv4_ifaces = {
        item.split("=", 1)[0]
        for item in ipv4_addresses
        if "=" in item
    }
    wifi_association: list[str] = []
    for iface in wifi_interfaces:
        association = _wifi_association_for_interface(system_name, iface)
        if (
            association == "(disconnected)"
            and iface in ipv4_ifaces
            and link_statuses.get(iface, "") == "active"
        ):
            association = "(uncertain: active link + IPv4 despite disconnect report)"
        wifi_association.append(f"{iface}={association}")

    tool_names = ["ip", "ifconfig", "iwconfig", "networksetup"]
    tool_availability = [f"{name}={'yes' if _which(name) else 'no'}" for name in tool_names]

    return {
        "hostname": platform.node() or "unknown",
        "os": _detect_os_label(system_name, kernel_release),
        "kernel": f"{system_name} {kernel_release}".strip() or "unknown",
        "architecture": platform.machine() or "unknown",
        "shell": os.environ.get("SHELL", "") or "unknown",
        "default_interface": default_interface,
        "default_interface_type": default_interface_type,
        "default_ipv4": default_ipv4,
        "default_gateway": default_gateway,
        "interfaces": interfaces,
        "link_statuses": link_statuses,
        "interface_types": interface_types,
        "wifi_interfaces": wifi_interfaces,
        "ethernet_interfaces": ethernet_interfaces,
        "virtual_interfaces": virtual_interfaces,
        "ipv4_addresses": ipv4_addresses,
        "virtual_ipv4_addresses": virtual_ipv4_addresses,
        "wifi_association": wifi_association,
        "network_source": network_source,
        "tool_availability": tool_availability,
        "uname": _run_command(["uname", "-a"]),
    }


def format_host_context_block(profile: dict[str, Any]) -> str:
    """Format host facts as a compact prompt block."""
    default_interface = str(profile.get("default_interface", "unknown") or "unknown")
    default_interface_type = str(profile.get("default_interface_type", "unknown") or "unknown")
    default_interface_display = (
        f"{default_interface} ({default_interface_type})"
        if default_interface != "unknown"
        else default_interface
    )
    default_ipv4 = str(profile.get("default_ipv4", "") or "unknown")
    default_gateway = str(profile.get("default_gateway", "") or "unknown")

    interfaces = ", ".join((profile.get("interfaces") or [])[:10]) or "unknown"
    ipv4_addresses = ", ".join((profile.get("ipv4_addresses") or [])[:10]) or "none detected"
    interface_types = profile.get("interface_types") or {}
    ordered_ifaces: list[str] = []
    for iface in (profile.get("interfaces") or []):
        if iface not in ordered_ifaces:
            ordered_ifaces.append(iface)
    for iface in interface_types:
        if iface not in ordered_ifaces:
            ordered_ifaces.append(iface)
    interface_roles = (
        ", ".join(
            f"{iface}:{interface_types.get(iface, 'unknown')}"
            for iface in ordered_ifaces[:10]
        )
        if ordered_ifaces
        else "unknown"
    )
    wifi_interfaces = ", ".join((profile.get("wifi_interfaces") or [])[:10]) or "none detected"
    ethernet_interfaces = ", ".join((profile.get("ethernet_interfaces") or [])[:10]) or "none detected"
    virtual_interfaces = ", ".join((profile.get("virtual_interfaces") or [])[:10]) or "none detected"
    wifi_interface_set = set(profile.get("wifi_interfaces") or [])
    ethernet_interface_set = set(profile.get("ethernet_interfaces") or [])
    wifi_association_map: dict[str, str] = {}
    for entry in profile.get("wifi_association") or []:
        if "=" not in entry:
            continue
        iface, value = entry.split("=", 1)
        wifi_association_map[iface] = value.strip()
    wifi_ipv4_values: list[str] = []
    active_wifi_ipv4_values: list[str] = []
    ethernet_ipv4_values: list[str] = []
    for item in profile.get("ipv4_addresses") or []:
        if "=" not in item:
            continue
        iface, _ip = item.split("=", 1)
        if iface in wifi_interface_set:
            wifi_ipv4_values.append(item)
            assoc = (wifi_association_map.get(iface, "unknown") or "").strip().lower()
            if assoc and assoc not in {"(disconnected)", "unknown"}:
                active_wifi_ipv4_values.append(item)
        elif iface in ethernet_interface_set:
            ethernet_ipv4_values.append(item)
    wifi_ipv4 = ", ".join(wifi_ipv4_values[:10]) or "none detected"
    active_wifi_ipv4 = ", ".join(active_wifi_ipv4_values[:10]) or "none detected"
    ethernet_ipv4 = ", ".join(ethernet_ipv4_values[:10]) or "none detected"
    virtual_ipv4 = ", ".join((profile.get("virtual_ipv4_addresses") or [])[:10]) or "none detected"
    wifi_association = ", ".join((profile.get("wifi_association") or [])[:10]) or "none detected"
    tool_availability = ", ".join(profile.get("tool_availability") or []) or "unknown"
    uname_line = str(profile.get("uname") or "").strip()
    if len(uname_line) > 200:
        uname_line = uname_line[:200] + "..."

    return "\n".join(
        [
            "## Host Environment (Auto-Detected)",
            "Use this profile for command/path choices. Do not assume Linux.",
            "Prefer the default interface/IP for current network routing decisions.",
            "If operator says they are on hotspot/Wi-Fi, prioritize Wi-Fi IPv4 over ethernet.",
            "Never treat virtual/tunnel IPs as hotspot truth.",
            f"- Hostname: {profile.get('hostname', 'unknown')}",
            f"- OS: {profile.get('os', 'unknown')}",
            f"- Kernel: {profile.get('kernel', 'unknown')}",
            f"- Architecture: {profile.get('architecture', 'unknown')}",
            f"- Shell: {profile.get('shell', 'unknown')}",
            f"- Default Interface: {default_interface_display}",
            f"- Default IPv4: {default_ipv4}",
            f"- Default Gateway: {default_gateway}",
            f"- Interfaces: {interfaces}",
            f"- Interface Roles: {interface_roles}",
            f"- Wi-Fi Interfaces: {wifi_interfaces}",
            f"- Ethernet Interfaces: {ethernet_interfaces}",
            f"- Virtual/Tunnel Interfaces: {virtual_interfaces}",
            f"- Wi-Fi Association: {wifi_association}",
            f"- Active (Associated) Wi-Fi IPv4 Addresses: {active_wifi_ipv4}",
            f"- Wi-Fi IPv4 Addresses: {wifi_ipv4}",
            f"- Ethernet IPv4 Addresses: {ethernet_ipv4}",
            f"- Virtual/Tunnel IPv4 Addresses: {virtual_ipv4}",
            f"- IPv4 Addresses: {ipv4_addresses}",
            f"- Network Source: {profile.get('network_source', 'none')}",
            f"- Tool Availability: {tool_availability}",
            f"- uname -a: {uname_line or 'unavailable'}",
        ]
    )


def build_host_context_block() -> str:
    """Build formatted host context block; never raises."""
    try:
        return format_host_context_block(collect_host_profile())
    except Exception:
        return (
            "## Host Environment (Auto-Detected)\n"
            "Use this profile for command/path choices. Do not assume Linux.\n"
            "- OS: unknown\n"
            "- Kernel: unknown\n"
            "- Interfaces: unknown\n"
        )
