import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class VmuxFuzzCiTests(unittest.TestCase):
    def read(self, relative_path: str) -> str:
        return (ROOT / relative_path).read_text(encoding="utf-8")

    def job(self, workflow: str, name: str) -> str:
        """The body of one job: from its header to the next job header."""
        match = re.search(
            r"^  " + re.escape(name) + r":\n(.*?)(?=^  [a-z0-9-]+:\n|\Z)",
            workflow,
            re.M | re.S,
        )
        if match is None:
            raise AssertionError(f"job {name} is missing")
        return match.group(1)

    def test_unit_workflow_runs_the_vmux_fuzz_targets(self) -> None:
        workflow = self.read(".github/workflows/test.yml")
        job = self.job(workflow, "vmux-fuzz")

        # The targets need the libFuzzer runtime and the static third-party
        # tree, so the job must build them and then run the checked-in corpus.
        self.assertIn("-DENABLE_VMUX_FUZZ_TEST=ON", job)
        self.assertIn("CMAKE_C_COMPILER=clang", job)
        self.assertIn("fuzz_vmux_ack fuzz_vmux_frame", job)
        self.assertIn("scripts/run-vmux-fuzz.sh", job)
        self.assertIn("scripts/build-third-party.sh", job)

    def test_the_fuzz_job_is_not_allowed_to_fail_silently(self) -> None:
        workflow = self.read(".github/workflows/test.yml")
        job = self.job(workflow, "vmux-fuzz")
        self.assertNotIn("continue-on-error", job)
        # The reproducers of a finding have to survive the run.
        self.assertIn("if: always()", job)
        self.assertIn("vmux-fuzz-corpus", job)

    def test_the_fuzz_targets_and_their_corpus_are_in_the_tree(self) -> None:
        for target in ("fuzz_vmux_ack", "fuzz_vmux_frame"):
            self.assertTrue(
                (ROOT / "tests" / "fuzz" / f"{target}.cpp").is_file(),
                f"{target} must exist",
            )
            corpus = ROOT / "tests" / "fuzz" / "corpus" / target
            self.assertTrue(corpus.is_dir(), f"{target} must ship a corpus")
            self.assertTrue(
                any(corpus.iterdir()),
                f"{target} must ship at least one seed",
            )

        self.assertTrue((ROOT / "tests/fuzz/dictionary/vmux.dict").is_file())
        self.assertTrue((ROOT / "scripts/run-vmux-fuzz.sh").is_file())

    def test_the_third_party_build_is_shared_by_the_workflows(self) -> None:
        # One script builds the tree the fuzz job links against, so the
        # dependencies it vendors cannot drift between the runs that reproduce
        # a finding.
        script = self.read("scripts/build-third-party.sh")
        self.assertIn("boost", script)
        self.assertIn("openssl", script)
        self.assertIn("jemalloc", script)

        # The linux build fetches the same versions inline instead of calling
        # the script, so it pins the versions itself; the shared script keeps
        # its defaults in step with it.
        self.assertIn(
            "scripts/build-third-party.sh",
            self.read(".github/workflows/test.yml"),
        )

    def test_the_third_party_versions_match_across_the_workflows(self) -> None:
        # The fuzz job builds the tree through the shared script, while the
        # linux build fetches the same versions inline.  A finding that
        # reproduces under one set of headers has to reproduce under the other
        # one, so the pinned versions may not drift apart.
        workflows = (
            ".github/workflows/test.yml",
            ".github/workflows/build-linux-amd64.yml",
        )
        for dependency in ("BOOST_VERSION", "OPENSSL_VERSION"):
            versions = set()
            for workflow in workflows:
                match = re.search(
                    r'^\s*' + dependency + r':\s*"([^"]+)"',
                    self.read(workflow),
                    re.M,
                )
                self.assertIsNotNone(match, f"{dependency} is missing in {workflow}")
                versions.add(match.group(1))
            self.assertEqual(
                len(versions),
                1,
                f"{dependency} differs between the workflows: {sorted(versions)}",
            )

            # The script pins the same default, so a workflow that forgets to
            # export the version still builds the tree the fuzz job tested.
            default = re.search(
                dependency + r"=\$\{" + dependency + r":-([^}]+)\}",
                self.read("scripts/build-third-party.sh"),
            )
            self.assertIsNotNone(default, f"{dependency} has no default in the script")
            self.assertIn(
                default.group(1),
                versions,
                f"the script default of {dependency} does not match the workflows",
            )


if __name__ == "__main__":
    unittest.main()
