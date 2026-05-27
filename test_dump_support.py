"""Unit tests for dump-file support.

Tests use only stdlib (unittest + unittest.mock) so they run without a
test framework dependency. CDB itself is never spawned — the
subprocess.Popen call is patched so we can assert the argv shape
without needing a real cdb.exe.
"""
from __future__ import annotations

import asyncio
import os
import tempfile
import unittest
from unittest import mock

import pydantic
from mcp.types import CallToolRequest, CallToolRequestParams

import cdb_session as cs
import server


def _call_tool_sync(srv, name, arguments):
    """Dispatch a tool call through the MCP server's CallToolRequest handler.

    Returns the inner CallToolResult so tests can check .content / .isError.
    """
    handler = srv.request_handlers[CallToolRequest]
    req = CallToolRequest(
        method="tools/call",
        params=CallToolRequestParams(name=name, arguments=arguments),
    )
    result = asyncio.run(handler(req))
    return result.root


def _make_test_server():
    """Build a Server instance without requiring a real cdb.exe.

    GPT Pro review #9: handler tests previously called create_server()
    directly, which invokes _find_cdb() at construction. That depends
    on the local environment.
    """
    with mock.patch.object(server, "_find_cdb", return_value="C:\\fake\\cdb.exe"):
        return server.create_server()


def _fake_session(session_kind="dump", dump_path=None, pid=0x1a2b):
    """A minimal CDBSession stand-in for handler integration tests."""
    sess = mock.MagicMock(spec=cs.CDBSession)
    sess.session_id = "fake-uuid"
    sess.session_kind = session_kind
    sess.dump_path = dump_path
    sess.pid = pid
    sess.state = "broken"
    return sess


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


class HardeningRegressionTests(unittest.TestCase):
    """Regression guards for the post-merge review findings (H1, H2)."""

    def test_foreach_blocked(self):
        # Reviewer B finding 1: .foreach takes a brace-delimited body that
        # the ;/newline splitter does not see inside.
        self.assertIsNotNone(cs.is_dangerous_command(
            ".foreach (x {lm}) { .shell whoami }"
        ))

    def test_do_blocked(self):
        self.assertIsNotNone(cs.is_dangerous_command(".do { .shell evil }"))

    def test_while_blocked(self):
        self.assertIsNotNone(cs.is_dangerous_command(".while (1) { .shell }"))

    def test_unc_dump_path_rejected(self):
        # Reviewer B finding 2: UNC dump paths were inconsistent with image
        # path validation — fixed in mcd-h1.
        with self.assertRaisesRegex(cs.CDBError, "UNC"):
            cs._validate_dump_path("\\\\evil-server\\share\\crash.dmp")

    def test_all_managed_extensions_classified(self):
        # Reviewer D finding: only `sos` was spot-checked in the original
        # `test_categorisation`. The dual-loadby handler branches on
        # _MANAGED_EXTENSIONS membership for ALL five names.
        for name in ("sos", "sosex", "mex", "psscor4", "netext"):
            with self.subTest(name=name):
                self.assertIn(name, server._MANAGED_EXTENSIONS)
                self.assertNotIn(name, server._BUILTIN_EXTENSIONS)
        for name in ("wow64exts", "exts"):
            with self.subTest(name=name):
                self.assertIn(name, server._BUILTIN_EXTENSIONS)
                self.assertNotIn(name, server._MANAGED_EXTENSIONS)

    def test_per_step_caps_match_design(self):
        # Reviewer D finding: only !analyze -v cap was guarded; if kn and
        # ~*kn swapped position, !analyze stays at 500 but stack-depth
        # changes silently.
        caps = {step[1]: step[2] for step in server._TRIAGE_STEPS}
        self.assertEqual(caps["kn"], 60)
        self.assertEqual(caps["~*kn"], 200)
        self.assertEqual(caps["lm"], 100)


class OpenDumpHandlerTests(unittest.TestCase):
    """End-to-end tests through the MCP CallToolRequest dispatcher."""

    def setUp(self):
        self.srv = _make_test_server()
        self.tmp = tempfile.mkdtemp()
        self.dump = _make_dump(self.tmp, "good.dmp", _USER_DUMP_MAGIC)
        # Reset module-level session state between tests.
        server._session = None

    def tearDown(self):
        server._session = None

    def _patch_open_dump(self, fake):
        return mock.patch.object(cs.CDBSession, "open_dump", return_value=fake)

    def _capture_mcp_error_codes(self, side_effect):
        """Run the handler and capture every McpError(ErrorData(...)) that
        the production code raises. The outer MCP framework swallows the
        code and exposes only the message text in the result, so we have
        to intercept at the ErrorData constructor to verify the code."""
        codes: list[int] = []
        real_error_data = server.ErrorData
        def recording_error_data(*args, **kwargs):
            instance = real_error_data(*args, **kwargs)
            codes.append(instance.code)
            return instance
        with mock.patch.object(
            cs.CDBSession, "open_dump", side_effect=side_effect,
        ), mock.patch.object(server, "ErrorData", recording_error_data):
            _call_tool_sync(
                self.srv, "cdb_open_dump",
                {"dump_path": "ignored.dmp", "auto_triage": False},
            )
        return codes

    def test_validation_error_maps_to_invalid_params(self):
        # mcd-h5 finding 7: CDBValidationError (path bad / suffix wrong /
        # kernel magic / etc.) → INVALID_PARAMS, distinct from operational
        # failures.
        from mcp.types import INVALID_PARAMS
        codes = self._capture_mcp_error_codes(
            cs.CDBValidationError("synthetic bad path"),
        )
        self.assertIn(INVALID_PARAMS, codes)

    def test_operational_error_maps_to_internal_error(self):
        # mcd-h5 finding 7: non-validation CDBError (cdb start failed,
        # init timeout, early exit) must NOT be classified as caller
        # input error.
        from mcp.types import INTERNAL_ERROR
        codes = self._capture_mcp_error_codes(
            cs.CDBError("synthetic cdb start failure"),
        )
        self.assertIn(INTERNAL_ERROR, codes)

    def test_auto_triage_false_returns_header_only(self):
        fake = _fake_session(dump_path=self.dump)
        with self._patch_open_dump(fake):
            res = _call_tool_sync(
                self.srv, "cdb_open_dump",
                {"dump_path": self.dump, "auto_triage": False},
            )
        self.assertFalse(res.isError)
        text = res.content[0].text
        self.assertIn("Auto-triage skipped", text)
        # The BEGIN/END framing only appears when the sweep actually ran.
        self.assertNotIn("BEGIN DEBUGGER OUTPUT", text)
        # session.send_command must NOT have been called for the sweep.
        fake.send_command.assert_not_called()

    def test_auto_triage_true_includes_begin_end_framing(self):
        fake = _fake_session(dump_path=self.dump)
        fake.send_command.return_value = "(stub output)"
        with self._patch_open_dump(fake):
            res = _call_tool_sync(
                self.srv, "cdb_open_dump",
                {"dump_path": self.dump, "auto_triage": True},
            )
        self.assertFalse(res.isError)
        text = res.content[0].text
        # Framing markers are a defence against prompt injection from
        # attacker-controlled symbol names. If they disappear, this test
        # catches it before merge.
        self.assertIn("--- BEGIN DEBUGGER OUTPUT (untrusted dump content) ---", text)
        self.assertIn("--- END DEBUGGER OUTPUT ---", text)

    def test_auto_triage_runs_canonical_steps_in_order(self):
        fake = _fake_session(dump_path=self.dump)
        fake.send_command.return_value = "stub"
        with self._patch_open_dump(fake):
            _call_tool_sync(
                self.srv, "cdb_open_dump",
                {"dump_path": self.dump, "auto_triage": True},
            )
        calls = [c.args[0] for c in fake.send_command.call_args_list]
        self.assertEqual(
            calls,
            [".lastevent", "!analyze -v", "kn", "~*kn", "lm"],
        )
        self.assertNotIn(".ecxr", calls, ".ecxr must NOT be in the unconditional sweep")

    def test_clr_hint_fires_when_lm_mentions_managed_runtime(self):
        fake = _fake_session(dump_path=self.dump)
        # send_command returns different text per call; the last call is `lm`.
        # Use side_effect to return CLR-mentioning text only for lm.
        outputs = {
            ".lastevent": "Last event: c0000005",
            "!analyze -v": "analysis stub",
            "kn": "stack stub",
            "~*kn": "all stacks stub",
            "lm": "00400000  myapp.exe\n7ffe0000  coreclr.dll",
        }
        fake.send_command.side_effect = lambda cmd, *a, **kw: outputs.get(cmd, "")
        with self._patch_open_dump(fake):
            res = _call_tool_sync(
                self.srv, "cdb_open_dump",
                {"dump_path": self.dump, "auto_triage": True},
            )
        text = res.content[0].text
        self.assertIn("cdb_load_extension", text, "CLR hint should fire when lm mentions coreclr")
        self.assertIn("sos", text)

    def test_clr_hint_absent_for_native_only_dump(self):
        fake = _fake_session(dump_path=self.dump)
        outputs = {
            ".lastevent": "Last event: c0000005",
            "!analyze -v": "analysis stub",
            "kn": "stack stub",
            "~*kn": "all stacks stub",
            "lm": "00400000  myapp.exe\n7ffe0000  kernel32.dll\n7fff0000  user32.dll",
        }
        fake.send_command.side_effect = lambda cmd, *a, **kw: outputs.get(cmd, "")
        with self._patch_open_dump(fake):
            res = _call_tool_sync(
                self.srv, "cdb_open_dump",
                {"dump_path": self.dump, "auto_triage": True},
            )
        text = res.content[0].text
        # Hints section is always emitted (contains the .ecxr reminder), but
        # the CLR-specific hint line must NOT appear.
        self.assertNotIn("CLR/CoreCLR modules detected", text)


class LoadExtensionHandlerTests(unittest.TestCase):
    """Reviewer A finding 2 + Reviewer D 1b: dispatch behaviour was untested."""

    def setUp(self):
        self.srv = _make_test_server()
        server._session = _fake_session(session_kind="dump")

    def tearDown(self):
        server._session = None

    def test_managed_extension_emits_both_loadby_commands(self):
        # The defining behaviour: avoid brittle error-text parsing by
        # running both .loadby <ext> clr AND .loadby <ext> coreclr.
        server._session.send_command.return_value = "stub"
        res = _call_tool_sync(self.srv, "cdb_load_extension", {"name": "sos"})
        self.assertFalse(res.isError)
        cmds = [c.args[0] for c in server._session.send_command.call_args_list]
        self.assertIn(".loadby sos clr", cmds)
        self.assertIn(".loadby sos coreclr", cmds)
        self.assertEqual(len(cmds), 2, "managed extensions should fire exactly two commands")

    def test_managed_netext_also_dual_loadby(self):
        # Regression guard for _MANAGED_EXTENSIONS completeness — if netext
        # were accidentally removed, this would emit a single .load instead.
        server._session.send_command.return_value = "stub"
        _call_tool_sync(self.srv, "cdb_load_extension", {"name": "netext"})
        cmds = [c.args[0] for c in server._session.send_command.call_args_list]
        self.assertIn(".loadby netext clr", cmds)
        self.assertIn(".loadby netext coreclr", cmds)

    def test_builtin_extension_uses_plain_load(self):
        server._session.send_command.return_value = "stub"
        _call_tool_sync(self.srv, "cdb_load_extension", {"name": "wow64exts"})
        cmds = [c.args[0] for c in server._session.send_command.call_args_list]
        self.assertEqual(cmds, [".load wow64exts"])

    def test_unknown_extension_rejected_at_dispatch(self):
        res = _call_tool_sync(
            self.srv, "cdb_load_extension", {"name": "evil_payload"},
        )
        self.assertTrue(res.isError)


class CdbGoBlockingTests(unittest.TestCase):
    """Reviewer D §9: gating via call_tool, not just the helper in isolation."""

    def setUp(self):
        self.srv = _make_test_server()

    def tearDown(self):
        server._session = None

    def test_cdb_go_blocked_on_dump_session(self):
        server._session = _fake_session(session_kind="dump")
        res = _call_tool_sync(self.srv, "cdb_go", {"command": "g"})
        self.assertTrue(res.isError)
        self.assertIn("dump", res.content[0].text)

    def test_cdb_break_blocked_on_dump_session(self):
        server._session = _fake_session(session_kind="dump")
        res = _call_tool_sync(self.srv, "cdb_break", {})
        self.assertTrue(res.isError)
        self.assertIn("dump", res.content[0].text)


class DetachDumpSessionTests(unittest.TestCase):
    """Reviewer A finding 1: dump detach must call close() not detach()."""

    def setUp(self):
        self.srv = _make_test_server()

    def tearDown(self):
        server._session = None

    def test_detach_on_dump_calls_close_not_detach(self):
        sess = _fake_session(session_kind="dump", dump_path="C:\\x.dmp")
        server._session = sess
        res = _call_tool_sync(self.srv, "cdb_detach", {})
        self.assertFalse(res.isError)
        sess.close.assert_called_once()
        sess.detach.assert_not_called()

    def test_detach_on_live_calls_detach(self):
        sess = _fake_session(session_kind="live-launch")
        server._session = sess
        res = _call_tool_sync(self.srv, "cdb_detach", {})
        self.assertFalse(res.isError)
        sess.detach.assert_called_once()
        sess.close.assert_not_called()


class GPTProHardeningTests(unittest.TestCase):
    """Regression guards for the GPT Pro post-merge review (mcd-h4, mcd-h5)."""

    # --- mcd-h4 finding 1: marker observation check ----------------------

    def test_initial_prompt_detects_cdb_early_exit(self):
        # If CDB exits without producing the initial prompt — corrupt dump,
        # missing image, etc. — the constructor must raise CDBError rather
        # than return a session that looks "broken". Either the
        # marker-observation check or the wait-timeout path is acceptable;
        # the invariant is that it does NOT silently succeed.
        # (Two code paths can win depending on the reader/main race.)
        with mock.patch("subprocess.Popen") as mock_popen:
            proc = mock.MagicMock()
            proc.poll.return_value = 0  # already exited
            proc.stdin = mock.MagicMock()
            # Empty iterator → reader exhausts loop → finally clause runs
            proc.stdout = iter([])
            mock_popen.return_value = proc
            with self.assertRaises(cs.CDBError) as ctx:
                cs.CDBSession(
                    cdb_path="C:\\fake\\cdb.exe",
                    args=["-z", "fake.dmp"],
                    session_kind="dump",
                    timeout=1,
                )
            msg = str(ctx.exception).lower()
            # Accept either the early-exit path (marker not observed) or
            # the timeout path. The bug we're guarding against is a SILENT
            # success, not a specific error message.
            self.assertTrue(
                "exited" in msg or "timed out" in msg or "initialization" in msg,
                f"unexpected message: {msg!r}",
            )

    # --- mcd-h4 finding 4: expanded blocklist ----------------------------

    def test_if_command_blocked(self):
        # .if (1) { .shell whoami } was the prior bypass; the splitter
        # cannot see inside { ... }.
        self.assertIsNotNone(cs.is_dangerous_command(".if (1) { .shell whoami }"))

    def test_for_command_blocked(self):
        self.assertIsNotNone(cs.is_dangerous_command(".for (r $t0 = 0; @$t0 < 5; r $t0 = @$t0 + 1) { .shell }"))

    def test_block_command_blocked(self):
        self.assertIsNotNone(cs.is_dangerous_command(".block { .shell evil }"))

    def test_catch_command_blocked(self):
        self.assertIsNotNone(cs.is_dangerous_command(".catch { .shell }"))

    def test_script_include_dollar_lt_blocked(self):
        # $<, $$<, $><, $$>< execute commands from a file — same risk class.
        for cmd in ("$< script.txt", "$$< script.txt", "$>< s.txt", "$$>< s.txt"):
            with self.subTest(cmd=cmd):
                self.assertIsNotNone(cs.is_dangerous_command(cmd))

    # --- mcd-h4 finding 5: slash-form UNC --------------------------------

    def test_forward_slash_unc_rejected_for_dump_path(self):
        # //server/share/x.dmp must be rejected the same as
        # \\\\server\\share\\x.dmp; previously slipped through.
        with self.assertRaisesRegex(cs.CDBError, "UNC"):
            cs._validate_dump_path("//evil-server/share/crash.dmp")

    def test_forward_slash_unc_rejected_for_search_path(self):
        with self.assertRaisesRegex(cs.CDBError, "UNC"):
            cs._validate_search_path("//evil-server/share")

    # --- mcd-h4 finding 7: validation-error subclass ---------------------

    def test_validation_errors_are_subclass_instances(self):
        # The discriminator the server uses to pick INVALID_PARAMS vs
        # INTERNAL_ERROR is whether the raised exception is a
        # CDBValidationError. Make sure all the validators actually raise it.
        with self.assertRaises(cs.CDBValidationError):
            cs._validate_dump_path("-evil.dmp")
        with self.assertRaises(cs.CDBValidationError):
            cs._validate_sympath("https://user@evil.com/x")
        with self.assertRaises(cs.CDBValidationError):
            cs._validate_search_path("\\\\evil\\share")
        # CDBValidationError IS a CDBError (subclass), so existing catches
        # that rely on the broader type still work.
        try:
            cs._validate_dump_path("-evil.dmp")
        except cs.CDBError:
            pass  # expected
        else:
            self.fail("CDBValidationError must be catchable as CDBError")

    # --- mcd-h5 finding 3: abort sweep on CDBError -----------------------

    def test_sweep_aborts_on_cdb_error_midway(self):
        # The handler used to `continue` past CDBError; now it must break,
        # because protocol may be desynchronised.
        srv = _make_test_server()
        fake = _fake_session(dump_path="C:\\x.dmp")
        # First two commands succeed, third raises, remaining must not run.
        call_log = []
        def fake_send(cmd, *a, **kw):
            call_log.append(cmd)
            if cmd == "kn":
                raise cs.CDBError("synthetic timeout")
            return "(stub)"
        fake.send_command.side_effect = fake_send
        with mock.patch.object(cs.CDBSession, "open_dump", return_value=fake):
            res = _call_tool_sync(
                srv, "cdb_open_dump",
                {"dump_path": "C:\\x.dmp", "auto_triage": True},
            )
        self.assertFalse(res.isError)
        text = res.content[0].text
        # Sweep should have called .lastevent and !analyze -v, then kn,
        # and then STOPPED — no ~*kn, no lm.
        self.assertEqual(call_log, [".lastevent", "!analyze -v", "kn"])
        self.assertIn("aborting remaining sweep", text)
        self.assertIn("Auto-triage aborted early", text)

    # --- mcd-h5 finding 6: independent .loadby attempts ------------------

    def test_load_extension_first_attempt_error_does_not_skip_second(self):
        # If `.loadby sos clr` raises CDBError, `.loadby sos coreclr` must
        # still run. Previously they shared a try-block.
        srv = _make_test_server()
        sess = _fake_session(session_kind="dump")
        call_log = []
        def fake_send(cmd, *a, **kw):
            call_log.append(cmd)
            if cmd == ".loadby sos clr":
                raise cs.CDBError("synthetic timeout on first attempt")
            return "(stub)"
        sess.send_command.side_effect = fake_send
        server._session = sess
        try:
            res = _call_tool_sync(srv, "cdb_load_extension", {"name": "sos"})
            self.assertFalse(res.isError)
            # Both runtimes must be attempted.
            self.assertEqual(call_log, [".loadby sos clr", ".loadby sos coreclr"])
            text = res.content[0].text
            self.assertIn("CDBError", text)  # first attempt's failure surfaced
            self.assertIn("coreclr", text)
        finally:
            server._session = None

    # --- mcd-h5 finding 8: PID format restored to decimal-primary --------

    def test_cdb_status_pid_is_decimal_primary(self):
        srv = _make_test_server()
        sess = _fake_session(session_kind="live-launch", pid=12345)
        server._session = sess
        try:
            res = _call_tool_sync(srv, "cdb_status", {})
            text = res.content[0].text
            # Decimal must appear; hex is acceptable as a parenthetical but
            # the previous decimal-scraping format is what callers expect.
            self.assertIn("12345", text)
            self.assertIn("0x3039", text)
        finally:
            server._session = None

    def test_cdb_status_dump_session_marks_pid_as_recorded(self):
        srv = _make_test_server()
        sess = _fake_session(
            session_kind="dump", dump_path="C:\\x.dmp", pid=0x1a2b,
        )
        server._session = sess
        try:
            res = _call_tool_sync(srv, "cdb_status", {})
            text = res.content[0].text
            self.assertIn("recorded, not live", text)
            self.assertIn("C:\\x.dmp", text)
        finally:
            server._session = None

    # --- mcd-h5 finding 10: section label rename -------------------------

    def test_section_label_is_current_thread_not_faulting(self):
        # .ecxr is intentionally skipped, so kn is the current thread, not
        # necessarily the faulting one. Label must reflect that.
        labels = [step[0] for step in server._TRIAGE_STEPS]
        self.assertNotIn("Faulting Thread Stack (kn)", labels)
        self.assertIn("Current Thread Stack (kn)", labels)


if __name__ == "__main__":
    unittest.main(verbosity=2)
