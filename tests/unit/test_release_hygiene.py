"""Release-hygiene tests: version metadata must never drift again.

1.0.14 shipped with the exe's version resource still saying 1.0.13
(253f373 fixed it after the fact) - the exact bug class this file pins
down. The version resource and the runtime __version__ must agree, and
the spec must actually wire the resource into the build.
"""
import os
import re
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))


def _read(name, binary=False):
    p = os.path.join(REPO_ROOT, name)
    mode = "rb" if binary else "r"
    with open(p, mode, encoding=None if binary else "utf-8-sig") as f:
        return f.read()


class TestVersionConsistency(unittest.TestCase):
    """tuntop_version_info.txt <-> tuntop/__init__.py <-> CHANGELOG.md."""

    def setUp(self):
        init = _read(os.path.join("tuntop", "__init__.py"))
        m = re.search(r'__version__\s*=\s*"(\d+\.\d+\.\d+)"', init)
        self.assertIsNotNone(m, "tuntop/__init__.py has no __version__")
        self.version = m.group(1)

        vi = _read("tuntop_version_info.txt")
        self.vi_text = vi
        m2 = re.search(r"filevers=\((\d+),\s*(\d+),\s*(\d+),", vi)
        self.assertIsNotNone(m2, "version resource has no filevers tuple")
        self.vi_tuple = tuple(int(g) for g in m2.groups())

    def test_resource_filevers_matches_init(self):
        want = tuple(int(p) for p in self.version.split("."))
        self.assertEqual(
            self.vi_tuple, want,
            f"tuntop_version_info.txt filevers {self.vi_tuple} != "
            f"__version__ {self.version} - this is the 1.0.14 drift bug; "
            "bump BOTH on release")

    def test_resource_strings_match_init(self):
        for field in ("FileVersion", "ProductVersion"):
            m = re.search(rf"StringStruct\('{field}',\s*'([^']+)'\)",
                          self.vi_text)
            self.assertIsNotNone(m, f"version resource missing {field}")
            self.assertEqual(
                m.group(1), self.version,
                f"{field} '{m.group(1)}' != __version__ {self.version}")

    def test_spec_wires_the_resource(self):
        spec = _read("TunTop.spec")
        self.assertIn(
            "tuntop_version_info.txt", spec,
            "TunTop.spec no longer references the version resource - "
            "exe properties would go blank/stale")

    def test_changelog_has_entry_for_current_version(self):
        cl = _read("CHANGELOG.md")
        self.assertRegex(
            cl, rf"## \[{re.escape(self.version)}\]",
            f"CHANGELOG.md has no section for __version__ {self.version} - "
            "document the release before tagging it")


if __name__ == "__main__":
    unittest.main()
