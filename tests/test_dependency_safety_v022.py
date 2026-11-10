# ProxyCircuit v0.2.2 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class DependencySafetyTests(unittest.TestCase):
    def test_websockets_pin_excludes_16(self):
        requirements = (ROOT / "requirements.txt").read_text()
        self.assertIn("websockets>=13,<16", requirements)
        self.assertNotIn("websockets>=13,<17", requirements)

    def test_update_checks_compatibility_before_ui_stop(self):
        update = (ROOT / "scripts/update-debian.sh").read_text()
        assert update.index("PY_DEPENDENCY_CHECK") < update.index("systemctl stop rpmgr-ui.service", update.index("echo '[1/5]"))
        self.assertIn("WebSocketsSansIOProtocol", update)
        self.assertIn('runuser -u rpmgr -- "$TARGET/venv/bin/python"', update)
        self.assertIn('chmod -R a+rX "$TARGET/venv"', update)

    def test_install_checks_compatibility(self):
        install = (ROOT / "scripts/install-debian.sh").read_text()
        self.assertIn("WebSocketsSansIOProtocol", install)
        self.assertIn('runuser -u rpmgr -- /opt/rpmgr/venv/bin/python', install)

if __name__ == "__main__":
    unittest.main()
