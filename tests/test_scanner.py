from app.scanner import NmapScanner


XML_RESULT = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" />
    <address addr="192.168.1.20" addrtype="ipv4" />
    <hostnames><hostname name="camera-lab" type="PTR" /></hostnames>
    <ports>
      <port protocol="tcp" portid="554"><state state="open" /><service name="rtsp" product="Video service" version="1.0" /></port>
      <port protocol="tcp" portid="22"><state state="closed" /><service name="ssh" /></port>
    </ports>
  </host>
</nmaprun>"""


def test_scanner_parses_open_services_and_camera_clues():
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return type("Result", (), {"returncode": 0, "stdout": XML_RESULT, "stderr": ""})()

    outcome = NmapScanner(run=fake_run).scan("192.168.1.20/32")

    assert len(outcome.hosts) == 1
    host = outcome.hosts[0]
    assert host["ip_address"] == "192.168.1.20"
    assert host["hostname"] == "camera-lab"
    assert host["probable_cctv_dvr"] is True
    assert [service["port"] for service in host["services"]] == [554]
    command, options = calls[0]
    assert "-sT" in command and "--version-light" in command
    assert "--script" not in command and "-sC" not in command
    assert options["timeout"] == 180


def test_non_camera_host_remains_unclassified():
    xml = (
      XML_RESULT.replace("portid=\"554\"", "portid=\"22\"")
      .replace('name="rtsp"', 'name="ssh"')
      .replace('product="Video service"', 'product="OpenSSH"')
    )
    scanner = NmapScanner(run=lambda *args, **kwargs: type("Result", (), {"returncode": 0, "stdout": xml, "stderr": ""})())

    host = scanner.scan("192.168.1.20/32").hosts[0]

    assert host["probable_cctv_dvr"] is False
    assert host["device_type"] == "Unknown network device"