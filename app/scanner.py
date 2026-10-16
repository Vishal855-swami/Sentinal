import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Callable


class ScannerError(RuntimeError):
    pass


class ScannerUnavailableError(ScannerError):
    pass


@dataclass
class ScanOutcome:
    hosts: list[dict]


class NmapScanner:
    camera_ports = {554, 8000, 8080, 8443, 8899, 9000, 37777, 34567}
    camera_terms = ("rtsp", "onvif", "hikvision", "dahua", "camera", "webcam", "video")

    def __init__(self, executable: str = "nmap", run: Callable = subprocess.run):
        self.executable = executable
        self.run = run

    def is_available(self) -> bool:
        return shutil.which(self.executable) is not None

    def scan(self, target: str) -> ScanOutcome:
        if not self.is_available() and self.run is subprocess.run:
            raise ScannerUnavailableError("Nmap is not installed or is not available on PATH.")

        command = [
            self.executable,
            "-n",
            "-T3",
            "-sT",
            "-sV",
            "--version-light",
            "-p",
            "21-23,53,80,81,443,554,5000,8000,8080,8443,8899,9000,34567,37777",
            "--max-retries",
            "2",
            "--host-timeout",
            "90s",
            "-oX",
            "-",
            "--",
            target,
        ]
        try:
            result = self.run(command, capture_output=True, text=True, timeout=180, check=False)
        except FileNotFoundError as exc:
            raise ScannerUnavailableError("Nmap is not installed or is not available on PATH.") from exc
        except subprocess.TimeoutExpired as exc:
            raise ScannerError("Nmap exceeded the 180-second scan limit.") from exc

        if result.returncode != 0:
            message = (result.stderr or "Nmap exited with an error.").strip()
            raise ScannerError(message[:500])

        try:
            root = ET.fromstring(result.stdout)
        except ET.ParseError as exc:
            raise ScannerError("Nmap returned invalid XML output.") from exc

        return ScanOutcome(hosts=[self._parse_host(host) for host in root.findall("host")])

    def _parse_host(self, host: ET.Element) -> dict:
        address = next(
            (item.get("addr") for item in host.findall("address") if item.get("addrtype") in ("ipv4", "ipv6")),
            "unknown",
        )
        hostname = next(
            (item.get("name") for item in host.findall("./hostnames/hostname") if item.get("name")),
            None,
        )
        services = []
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            services.append(
                {
                    "protocol": port.get("protocol", "tcp"),
                    "port": int(port.get("portid", "0")),
                    "name": service.get("name", "unknown") if service is not None else "unknown",
                    "product": service.get("product", "") if service is not None else "",
                    "version": service.get("version", "") if service is not None else "",
                }
            )

        clues = []
        for service in services:
            service_text = " ".join((service["name"], service["product"], service["version"])).lower()
            if service["port"] in self.camera_ports:
                clues.append(f"TCP port {service['port']} is commonly associated with video devices")
            if any(term in service_text for term in self.camera_terms):
                clues.append(f"Service identification contains: {service['name']} {service['product']}")

        return {
            "ip_address": address,
            "hostname": hostname,
            "probable_cctv_dvr": bool(clues),
            "device_type": "Probable CCTV/DVR" if clues else "Unknown network device",
            "identification_evidence": list(dict.fromkeys(clues)),
            "services": services,
        }