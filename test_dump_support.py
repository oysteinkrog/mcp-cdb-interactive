"""Unit tests for dump-file support.

Tests use only stdlib (unittest + unittest.mock) so they run without a
test framework dependency. CDB itself is never spawned — the
subprocess.Popen call is patched so we can assert the argv shape
without needing a real cdb.exe.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

import pydantic

import cdb_session as cs
import server


# Bytes we use to fabricate fixture dumps. Real dumps start with their
# format magic; what we need is just (a) something that does NOT match
# the kernel-dump magics and (b) something that does.
_USER_DUMP_MAGIC = b"MDMP\x93\xa7\x00\x00"
_KERNEL_DUMP_MAGIC_PAE = b"PAGEDU64"
_KERNEL_DUMP_MAGIC_X86 = b"PAGEDUMP"


def _make_dump(dir_path: str, name: str, magic: bytes) -> str:
    path = os.path.join(dir_path, name)
    with open(path, "wb") as f:
        f.write(magic)
        f.write(b"\x00" * 100)
    return path


class DangerousPatternsTests(unittest.TestCase):
    def test_new_patterns_blocked(self):
        for cmd in (".cordll", ".net", ".dvalloc", ".dvfree"):
            with self.subTest(cmd=cmd):
                self.assertIsNotNone(cs.is_dangerous_command(cmd))

    def test_existing_patterns_still_blocked(self):
        for cmd in (".shell echo", ".loadby sos clr", "!shell"):
            with self.subTest(cmd=cmd):
                self.assertIsNotNone(cs.is_dangerous_command(cmd))

    def test_safe_commands_pass(self):
        for cmd in ("kb", "!analyze -v", "lm", "r"):
            with self.subTest(cmd=cmd):
                self.assertIsNone(cs.is_dangerous_command(cmd))

    def test_allow_dangerous_bypass(self):
        self.assertIsNone(cs.is_dangerous_command(".shell whoami", allow_dangerous=True))


class ValidateDumpPathTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.valid = _make_dump(self.tmp, "good.dmp", _USER_DUMP_MAGIC)

    def test_valid_dump_path(self):
        cs._validate_dump_path(self.valid)  # no exception

    def test_missing_file(self):
        with self.assertRaisesRegex(cs.CDBError, "not found"):
            cs._validate_dump_path(os.path.join(self.tmp, "nope.dmp"))

    def test_bad_suffix(self):
        path = os.path.join(self.tmp, "x.txt")
        with open(path, "wb") as f:
            f.write(_USER_DUMP_MAGIC)
        with self.assertRaisesRegex(cs.CDBError, "Unsupported dump file extension"):
            cs._validate_dump_path(path)

    def test_leading_dash_rejected(self):
        with self.assertRaisesRegex(cs.CDBError, "cannot start with"):
            cs._validate_dump_path("-evil.dmp")

    def test_unsafe_chars_rejected(self):
        with self.assertRaisesRegex(cs.CDBError, "unsafe characters"):
            cs._validate_dump_path("foo;bar.dmp")

    def test_odd_trailing_backslashes_rejected(self):
        with self.assertRaisesRegex(cs.CDBError, "trailing backslash"):
            cs._validate_dump_path("C:\\foo.dmp\\")

    def test_kernel_dump_pagedu64_rejected(self):
        path = _make_dump(self.tmp, "kernel64.dmp", _KERNEL_DUMP_MAGIC_PAE)
        with self.assertRaisesRegex(cs.CDBError, "Kernel-mode dump"):
            cs._validate_dump_path(path)

    def test_kernel_dump_pagedump_rejected(self):
        path = _make_dump(self.tmp, "kernel32.dmp", _KERNEL_DUMP_MAGIC_X86)
        with self.assertRaisesRegex(cs.CDBError, "Kernel-mode dump"):
            cs._validate_dump_path(path)


class ValidateSympathTests(unittest.TestCase):
    def test_srv_with_url(self):
        cs._validate_sympath("SRV*C:\\cache*https://msdl.microsoft.com/download/symbols")

    def test_semicolon_separated_dirs(self):
        cs._validate_sympath("C:\\a;C:\\b;C:\\c")

    def test_plain_url(self):
        cs._validate_sympath("https://msdl.microsoft.com/download/symbols")

    def test_url_with_credentials_rejected(self):
        with self.assertRaisesRegex(cs.CDBError, "Invalid"):
            cs._validate_sympath("https://user@evil.example.com/sym")

    def test_newline_injection_rejected(self):
        with self.assertRaisesRegex(cs.CDBError, "Invalid"):
            cs._validate_sympath("C:\\a\nbad")

    def test_too_long_rejected(self):
        with self.assertRaisesRegex(cs.CDBError, "too long"):
            cs._validate_sympath("x" * 4096)


class ValidateSearchPathTests(unittest.TestCase):
    def test_semicolon_separated(self):
        cs._validate_search_path("C:\\bin;C:\\lib")

    def test_unc_rejected(self):
        with self.assertRaisesRegex(cs.CDBError, "UNC"):
            cs._validate_search_path("\\\\server\\share")

    def test_quote_rejected(self):
        with self.assertRaisesRegex(cs.CDBError, "Invalid"):
            cs._validate_search_path('C:\\foo"bar')


class OpenDumpArgvTests(unittest.TestCase):
    """Patch CDBSession.__init__ so we can assert the argv built by open_dump."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.dump = _make_dump(self.tmp, "good.dmp", _USER_DUMP_MAGIC)

    def _capture_open(self, **kwargs):
        captured = {}

        def fake_init(self, cdb_path, args, *, session_kind, timeout=30, verbose=False):
            captured["cdb_path"] = cdb_path
            captured["args"] = list(args)
            captured["session_kind"] = session_kind
            captured["timeout"] = timeout
            self.session_id = "test"
            self.session_kind = session_kind
            self.dump_path = None
            self._target_pid = None
            self._state = "broken"

        with mock.patch.object(cs.CDBSession, "__init__", fake_init), \
             mock.patch.object(cs, "_find_cdb", return_value="C:\\fake\\cdb.exe"):
            sess = cs.CDBSession.open_dump(self.dump, **kwargs)
        return captured, sess

    def test_z_flag_present(self):
        captured, _ = self._capture_open()
        self.assertIn("-z", captured["args"])

    def test_no_live_only_flags(self):
        captured, _ = self._capture_open()
        self.assertNotIn("-G", captured["args"], "live-only -G must not be passed in dump mode")
        self.assertNotIn("-o", captured["args"], "live-only -o must not be passed in dump mode")

    def test_session_kind_is_dump(self):
        _, sess = self._capture_open()
        self.assertEqual(sess.session_kind, "dump")

    def test_dump_path_cached(self):
        _, sess = self._capture_open()
        self.assertEqual(sess.dump_path, self.dump)

    def test_default_timeout_is_300(self):
        captured, _ = self._capture_open()
        self.assertEqual(captured["timeout"], 300)

    def test_symbol_path_precedes_z(self):
        captured, _ = self._capture_open(symbol_path="SRV*C:\\c*https://msdl.microsoft.com/download/symbols")
        args = captured["args"]
        self.assertLess(args.index("-y"), args.index("-z"))
        self.assertEqual(args[args.index("-y") + 1].split("*")[0], "SRV")

    def test_image_path_precedes_z(self):
        captured, _ = self._capture_open(image_path="C:\\bin;C:\\lib")
        args = captured["args"]
        self.assertLess(args.index("-i"), args.index("-z"))
        self.assertEqual(args[args.index("-i") + 1], "C:\\bin;C:\\lib")


class SessionKindRequiredTests(unittest.TestCase):
    def test_missing_session_kind_raises(self):
        with self.assertRaises(TypeError):
            # session_kind is keyword-only and required, no default
            cs.CDBSession(cdb_path="x", args=["y"])

    def test_invalid_session_kind_rejected(self):
        with self.assertRaisesRegex(cs.CDBError, "Invalid session_kind"):
            cs.CDBSession(cdb_path="x", args=["y"], session_kind="bogus")


class ServerGatingTests(unittest.TestCase):
    def test_require_live_session_blocks_dump(self):
        from mcp.shared.exceptions import McpError

        class S:
            session_kind = "dump"

        with self.assertRaises(McpError) as ctx:
            server._require_live_session(S(), "cdb_go")
        self.assertIn("dump", ctx.exception.error.message)

    def test_require_live_session_allows_launch(self):
        class S:
            session_kind = "live-launch"
        server._require_live_session(S(), "cdb_go")  # no exception

    def test_require_live_session_allows_attach(self):
        class S:
            session_kind = "live-attach"
        server._require_live_session(S(), "cdb_break")  # no exception


class LoadExtensionParamsTests(unittest.TestCase):
    def test_all_allowlisted_accepted(self):
        for name in ("sos", "sosex", "mex", "psscor4", "netext", "wow64exts", "exts"):
            with self.subTest(name=name):
                p = server.CdbLoadExtensionParams(name=name)
                self.assertEqual(p.name, name)

    def test_unknown_extension_rejected(self):
        with self.assertRaises(pydantic.ValidationError):
            server.CdbLoadExtensionParams(name="badname")

    def test_path_like_name_rejected(self):
        with self.assertRaises(pydantic.ValidationError):
            server.CdbLoadExtensionParams(name="C:\\evil.dll")

    def test_categorisation(self):
        self.assertIn("sos", server._MANAGED_EXTENSIONS)
        self.assertIn("wow64exts", server._BUILTIN_EXTENSIONS)
        self.assertNotIn("sos", server._BUILTIN_EXTENSIONS)


class TriageHelpersTests(unittest.TestCase):
    def test_ecxr_not_in_sweep(self):
        """Regression guard: .ecxr would mutate context on hang dumps."""
        cmds = [step[1] for step in server._TRIAGE_STEPS]
        self.assertNotIn(".ecxr", cmds)

    def test_sweep_includes_canonical_steps(self):
        cmds = [step[1] for step in server._TRIAGE_STEPS]
        for expected in (".lastevent", "!analyze -v", "kn", "~*kn", "lm"):
            self.assertIn(expected, cmds)

    def test_analyze_v_cap_is_generous(self):
        cap_by_cmd = {step[1]: step[2] for step in server._TRIAGE_STEPS}
        self.assertGreaterEqual(cap_by_cmd["!analyze -v"], 500)

    def test_cap_section_under(self):
        text = "a\nb\nc"
        self.assertEqual(server._cap_section(text, 10, "cmd"), text)

    def test_cap_section_over_includes_retrieval(self):
        text = "\n".join(f"l{i}" for i in range(50))
        capped = server._cap_section(text, 10, "kn 100")
        self.assertIn("truncated", capped)
        self.assertIn("kn 100", capped)
        self.assertIn("40 more lines", capped)

    def test_cap_section_empty(self):
        self.assertEqual(server._cap_section("", 10, "x"), "(no output)")

    def test_clr_detection(self):
        self.assertTrue(server._detect_clr("0`00007fff CLR.dll loaded"))
        self.assertTrue(server._detect_clr("mscorlib.dll"))
        self.assertTrue(server._detect_clr("System.Private.CoreLib.dll"))
        self.assertFalse(server._detect_clr("kernel32.dll user32.dll"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
