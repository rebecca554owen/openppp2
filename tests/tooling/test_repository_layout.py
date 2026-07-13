import tempfile
import unittest
from pathlib import Path

from tools import check_repository_layout


class RepositoryLayoutTests(unittest.TestCase):
    def fixture(self, files: dict[str, str]) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for relative, contents in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents, encoding="utf-8")
        return root

    def assert_violation(self, root: Path, expected: str) -> None:
        violations = check_repository_layout.check_repository(root)
        self.assertTrue(
            any(expected in violation for violation in violations),
            f"missing {expected!r} in {violations!r}",
        )

    def test_protocol_cannot_include_client(self) -> None:
        root = self.fixture(
            {
                "ppp/app/protocol/Bad.h": (
                    "#include <ppp/app/client/VEthernetExchanger.h>\n"
                ),
            }
        )
        self.assert_violation(root, "protocol -> client/server")

    def test_client_cannot_include_server(self) -> None:
        root = self.fixture(
            {
                "ppp/app/client/Bad.cpp": (
                    "#include <ppp/app/server/VirtualEthernetSwitcher.h>\n"
                ),
            }
        )
        self.assert_violation(root, "client -> server")

    def test_route_public_header_cannot_expose_switcher(self) -> None:
        root = self.fixture(
            {
                "ppp/app/client/route/Bad.h": (
                    "class VEthernetNetworkSwitcher;\n"
                ),
            }
        )
        self.assert_violation(root, "route/DNS public API exposes concrete host")

    def test_dns_public_header_cannot_expose_exchanger(self) -> None:
        root = self.fixture(
            {
                "ppp/app/client/dns/Bad.h": "class VEthernetExchanger;\n",
            }
        )
        self.assert_violation(root, "route/DNS public API exposes concrete host")

    def test_route_ports_cannot_return_mutable_container_pointer(self) -> None:
        root = self.fixture(
            {
                "ppp/app/client/route/Bad.h": (
                    "ppp::function<ppp::unordered_set<uint32_t>*()> values;\n"
                ),
            }
        )
        self.assert_violation(root, "mutable container pointer in public API")

    def test_new_inc_fragment_is_rejected(self) -> None:
        root = self.fixture(
            {"ppp/app/client/NewMembers.inc": "int value_;\n"}
        )
        self.assert_violation(root, "new .inc declaration fragment")

    def test_existing_switcher_inc_fragments_are_grandfathered(self) -> None:
        root = self.fixture(
            {
                "ppp/app/client/VEthernetNetworkSwitcherMembers.inc": (
                    "int value_;\n"
                ),
            }
        )
        self.assertEqual([], check_repository_layout.check_repository(root))


if __name__ == "__main__":
    unittest.main()
