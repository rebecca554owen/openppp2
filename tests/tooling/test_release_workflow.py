import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class ReleaseWorkflowTests(unittest.TestCase):
    def test_release_publishes_only_nonempty_distributable_assets(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")

        self.assertIn("find artifacts -type f -size +0c", workflow)
        self.assertIn("-name '*.zip'", workflow)
        self.assertIn("-name '*.tar.gz'", workflow)
        self.assertIn("-name '*.apk'", workflow)
        self.assertIn("files: release-assets/*", workflow)
        self.assertIn("fail_on_unmatched_files: true", workflow)
        self.assertNotIn("files: artifacts/**/*", workflow)


if __name__ == "__main__":
    unittest.main()
