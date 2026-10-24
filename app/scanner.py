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
    recorder_terms = ("nvr", "dvr", "video recorder", "network video recorder")
    camera_terms = ("ip camera", "camera", "webcam", "cctv")
    video_terms = ("rtsp", "onvif", "video")
    surveillance_vendors = ("hikvision", "dahua", "uniview", "reolink", "amcrest", "axis")

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

        device_type, probable_cctv_dvr, clues = self._classify_device(services)

        return {
            "ip_address": address,
            "hostname": hostname,
            "probable_cctv_dvr": probable_cctv_dvr,
            "device_type": device_type,
            "identification_evidence": clues,
            "services": services,
        }

    def _classify_device(self, services: list[dict]) -> tuple[str, bool, list[str]]:
        service_texts = [
            " ".join((service["name"], service["product"], service["version"])).lower()
            for service in services
        ]
        combined_text = " ".join(service_texts)
        clues = []

        if any(term in combined_text for term in self.recorder_terms):
            clues.append("Service identification contains explicit video-recorder terms")
            return "Probable video recorder", True, clues
        if any(term in combined_text for term in self.camera_terms):
            clues.append("Service identification contains camera-related terms")
            return "Probable IP camera", True, clues
        if any(term in combined_text for term in self.surveillance_vendors):
            clues.append("Service identification contains a known surveillance-vendor name")
            return "Probable CCTV/DVR", True, clues

        recorder_ports = [service["port"] for service in services if service["port"] in {37777, 34567}]
        if recorder_ports:
            clues.extend(
                f"TCP port {port} is commonly associated with video-recorder management"
                for port in recorder_ports
            )
            return "Probable video recorder", True, clues

        video_services = [
            service for service, text in zip(services, service_texts)
            if any(term in text for term in self.video_terms) or service["port"] == 554
        ]
        if video_services:
            for service in video_services:
                clues.append(f"Video-related service observed: {service['name']} on TCP/{service['port']}")
            return "Probable video endpoint", True, list(dict.fromkeys(clues))

        surveillance_ports = [
            service["port"] for service in services
            if service["port"] in self.camera_ports - {8080, 8443}
        ]
        if surveillance_ports:
            clues.extend(
                f"TCP port {port} is sometimes associated with video devices"
                for port in surveillance_ports
            )
            return "Possible video surveillance device", True, clues

        service_names = {service["name"].lower() for service in services}
        if service_names.intersection({"http", "https", "http-proxy"}):
            clues.append("An HTTP or HTTPS service is exposed")
            return "Web-managed network device", False, clues
        if service_names.intersection({"ssh", "telnet"}):
            clues.append("A remote-management service is exposed")
            return "Remote-management device", False, clues
        return "Unknown network device", False, clues