#!/usr/bin/env python3
import base64
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock
from opencode_agent_task_pilot.evidence import stream_provider_usage
from opencode_agent_task_pilot.replay import decode_sources

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "pilot", ROOT / "scripts/opencode-agent-task-pilot.py"
)
pilot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pilot)


class PilotTests(unittest.TestCase):
    def test_replay_source_archive_rejects_escape_and_changed_bytes(self):
        body = b"fn main() {}"
        row = {"base64": base64.b64encode(body).decode(), "bytes": len(body),
               "sha256": hashlib.sha256(body).hexdigest()}
        self.assertEqual(decode_sources({"src/main.spx": row}), {"src/main.spx": body})
        for path in ("../main.spx", "/main.spx", "src/../main.spx", "src//main.spx"):
            with self.assertRaises(ValueError):
                decode_sources({path: row})
        with self.assertRaises(ValueError):
            decode_sources({"src/main.spx": dict(row, sha256="0" * 64)})

    def test_policy_denies_network_subagents_and_external_paths(self):
        config = pilot.policy()
        self.assertEqual(config["model"], pilot.MODEL)
        self.assertEqual(config["agent"][pilot.AGENT]["model"], pilot.MODEL)
        permissions = config["agent"][pilot.AGENT]["permission"]
        self.assertEqual(permissions["webfetch"], "deny")
        self.assertEqual(permissions["task"], "deny")
        self.assertEqual(permissions["external_directory"], "deny")

    def test_graph_lane_denies_native_source_tools(self):
        permissions = pilot.policy("semaprax-graph-operational")["agent"][pilot.AGENT]["permission"]
        for tool in ("read", "glob", "grep", "list", "edit"):
            self.assertEqual(permissions[tool], "deny")
        self.assertEqual(permissions["bash"], {"*": "deny"})
        self.assertEqual(permissions["semaprax_*"], "allow")

    def test_new_evidence_required(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(pilot.PilotFailure):
                pilot.run_tuple(
                    "signature-migration-v1",
                    "semaprax-source-first",
                    1,
                    "unused",
                    str(Path(sys.executable).resolve(strict=True)),
                    Path(temp),
                )

    def test_archived_provider_counters_do_not_estimate_tokens(self):
        body = (ROOT / "scripts/fixtures/opencode-provider-smoke-v1/session.json").read_bytes()
        counters = pilot.provider_usage(body, pilot.MODEL)
        self.assertEqual(counters["status"], "observed")
        self.assertEqual((counters["model_input_tokens"], counters["model_output_tokens"]), (4437, 214))

    def test_exported_usage_keeps_cached_and_reasoning_tokens(self):
        exported = json.loads((ROOT / "scripts/fixtures/opencode-provider-smoke-v1/session.json").read_bytes())
        tokens = exported["messages"][1]["info"]["tokens"]
        tokens["cache"] = {"read": 7, "write": 3}
        usage = pilot.provider_usage(json.dumps(exported).encode(), pilot.MODEL)
        self.assertEqual((usage["model_input_tokens"], usage["model_output_tokens"]), (4447, 214))
        del tokens["reasoning"]
        self.assertEqual(pilot.provider_usage(json.dumps(exported).encode(), pilot.MODEL)["status"], "unavailable")

    def test_stream_provider_usage_binds_each_finish_to_session_and_model(self):
        session = "ses_observed"
        event = lambda step, message, input_tokens, output_tokens: {
            "type": "step_finish", "sessionID": session,
            "part": {"type": "step-finish", "id": step, "messageID": message,
                     "sessionID": session,
                     "tokens": {"input": input_tokens, "output": output_tokens,
                                "reasoning": 2, "cache": {"read": 3, "write": 1}}},
        }
        body = b"\n".join(json.dumps(item).encode() for item in (
            {"type": "step_start", "sessionID": session, "part": {}},
            event("prt_one", "msg_one", 7, 3), event("prt_two", "msg_two", 11, 5),
        ))
        counters = stream_provider_usage(body, session, pilot.MODEL)
        self.assertEqual(counters["status"], "observed")
        self.assertEqual(counters["method"], "configured-model CLI stream report")
        self.assertEqual((counters["model_input_tokens"], counters["model_output_tokens"]), (26, 12))
        duplicate = stream_provider_usage(
            body + b"\n" + json.dumps(event("prt_two", "msg_three", 1, 1)).encode(),
            session, pilot.MODEL,
        )
        self.assertEqual(duplicate["status"], "unavailable")
        wrong_session = stream_provider_usage(body, "ses_other", pilot.MODEL)
        self.assertEqual(wrong_session["status"], "unavailable")

    def test_gateway_counter_excludes_harness_drift(self):
        event = lambda argv, out, err, code: {
            "argv_b64": pilot.base64.b64encode(argv).decode(),
            "stdout_b64": pilot.base64.b64encode(out).decode(),
            "stderr_b64": pilot.base64.b64encode(err).decode(),
            "returncode": code,
        }
        body = b"\n".join(
            json.dumps(item).encode()
            for item in (event(b"graph\0src/core.spx", b"{}", b"", 0), event(b"pilot-drift\0graph", b"", b"", 0))
        )
        diagnostics = pilot.gateway_diagnostics(body)
        self.assertEqual(diagnostics["gateway_invocations"], 1)
        self.assertEqual(diagnostics["gateway_argv_bytes"], len(b"graph\0src/core.spx"))


class SubprocessBoundaryTests(unittest.TestCase):
    def test_gateway_rejects_embedded_absolute_output_path(self):
        with tempfile.TemporaryDirectory(prefix="spx-gateway-test-") as temp:
            state = Path(temp)
            candidate = state / "candidate"
            (candidate / "src").mkdir(parents=True)
            (candidate / "src/core.spx").write_text("module sample;\n")
            gateway, _, _, configuration = pilot.install_gateway(
                Path(sys.executable).resolve(strict=True), state, candidate,
                "semaprax-graph-operational",
            )
            environment = dict(os.environ, SEMAPRAX_PILOT_GATEWAY=configuration)
            completed = subprocess.run(
                [gateway, "graph", "--output=/tmp/pilot-escape"],
                env=environment, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, check=False,
            )
            self.assertEqual(completed.returncode, 126)
            self.assertIn(b"option path escapes candidate", completed.stderr)

    def test_source_write_refuses_a_stale_precondition(self):
        with tempfile.TemporaryDirectory(prefix="spx-gateway-test-") as temp:
            state = Path(temp)
            candidate = state / "candidate"
            target = candidate / "src/core.spx"
            target.parent.mkdir(parents=True)
            target.write_text("module before;\n")
            gateway, _, _, configuration = pilot.install_gateway(
                pilot.provision_semaprax(Path(sys.executable).resolve(strict=True), state)[0],
                state, candidate, "semaprax-source-first",
            )
            environment = dict(os.environ, SEMAPRAX_PILOT_GATEWAY=configuration)
            stale_digest = pilot.sha(target.read_bytes())
            target.write_text("module injected;\n")
            completed = subprocess.run(
                [gateway, "pilot-write-source", "src/core.spx", stale_digest,
                 pilot.base64.b64encode(b"module overwrite;\n").decode()],
                env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            self.assertEqual(completed.returncode, 126)
            self.assertEqual(target.read_text(), "module injected;\n")
            self.assertIn(b"precondition is stale", completed.stderr)

    def test_output_cap_kills_continuous_writer(self):
        old = pilot.CAP
        pilot.CAP = 1024
        try:
            with self.assertRaisesRegex(pilot.PilotFailure, "output cap"):
                pilot.bounded(
                    [
                        sys.executable,
                        "-c",
                        "import sys\nwhile True: sys.stdout.write('x'*512);sys.stdout.flush()",
                    ],
                    ROOT,
                    2,
                )
        finally:
            pilot.CAP = old

    def test_closed_pipes_still_obey_timeout(self):
        with self.assertRaisesRegex(pilot.PilotFailure, "timed out"):
            pilot.bounded(
                [
                    sys.executable,
                    "-c",
                    "import os,time;os.close(1);os.close(2);time.sleep(2)",
                ],
                ROOT,
                0.02,
            )

    def test_exited_parent_cannot_leave_quiet_pipe_descendant(self):
        with tempfile.TemporaryDirectory(prefix="spx-descendant-test-") as temp:
            pid_file = Path(temp) / "pid"
            child_code = f"import os, pathlib, time; pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid())); time.sleep(5)"
            code = f"import subprocess, sys, time; subprocess.Popen([sys.executable, '-c', {child_code!r}]); time.sleep(0.1); print('parent done')"
            start = time.monotonic()
            pilot.bounded([sys.executable, "-c", code], ROOT, 2)
            self.assertLess(time.monotonic() - start, 1)
            for _ in range(20):
                if pid_file.exists():
                    break
                time.sleep(0.01)
            self.assertTrue(pid_file.exists())
            pid = int(pid_file.read_text())
            for _ in range(50):
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.01)
            else:
                self.fail("quiet-pipe descendant survived process-group cleanup")

    def test_compiler_source_must_be_regular_non_symlink_executable(self):
        with tempfile.TemporaryDirectory(prefix="spx-compiler-test-") as temp:
            root = Path(temp)
            nonexec = root / "nonexec"
            nonexec.write_text("compiler")
            with self.assertRaisesRegex(pilot.PilotFailure, "regular executable"):
                pilot.provision_semaprax(nonexec, root / "state")
            link = root / "link"
            link.symlink_to(Path(sys.executable).resolve(strict=True))
            with self.assertRaisesRegex(pilot.PilotFailure, "non-symlink"):
                pilot.provision_semaprax(link, root / "state")

    @unittest.skipUnless(shutil.which("sandbox-exec"), "sandbox-exec unavailable")
    def test_saved_profile_denies_directory_descendants_and_outside_write(self):
        with tempfile.TemporaryDirectory(prefix="spx-profile-test-") as temp:
            root = Path(temp).resolve()
            candidate = root / "candidate"
            protected = root / "protected"
            state = root / "state"
            for directory in (candidate, protected, state):
                directory.mkdir()
            allowed = candidate / "fixture.txt"
            hidden = protected / "nested" / "rubric.json"
            hidden.parent.mkdir()
            allowed.write_text("candidate")
            hidden.write_text("rubric")
            profile = state / "seatbelt.sb"
            profile.write_text(pilot.seatbelt_profile(candidate, (protected,), state))
            pilot.seatbelt_probe(profile, allowed, (hidden,), candidate, state)
            self.assertFalse((candidate / ".seatbelt-probe").exists())
            self.assertFalse((state / ".seatbelt-probe").exists())

    @unittest.skipUnless(shutil.which("sandbox-exec"), "sandbox-exec unavailable")
    def test_probe_rejects_the_old_directory_literal_rule(self):
        with tempfile.TemporaryDirectory(prefix="spx-old-profile-test-") as temp:
            root = Path(temp).resolve()
            candidate = root / "candidate"
            protected = root / "protected"
            state = root / "state"
            for directory in (candidate, protected, state):
                directory.mkdir()
            allowed = candidate / "fixture.txt"
            hidden = protected / "rubric.json"
            allowed.write_text("candidate")
            hidden.write_text("rubric")
            profile = state / "old-seatbelt.sb"
            profile.write_text(
                "(version 1)\n(allow default)\n"
                f'(deny file-read* (literal "{protected}"))\n'
                f'(deny file-write* (require-not (require-any (subpath "{candidate}") (subpath "{state}"))))\n'
            )
            with self.assertRaisesRegex(
                pilot.PilotFailure, "read protected descendant"
            ):
                pilot.seatbelt_probe(profile, allowed, (hidden,), candidate, state)


class TupleTransportTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("sandbox-exec"), "sandbox-exec unavailable")
    def test_source_and_graph_wrapped_runs_archive_their_boundary_proof(self):
        with tempfile.TemporaryDirectory(prefix="spx-stub-test-") as temp:
            root = Path(temp).resolve()
            evidence_parent = root / "evidence-parent"
            evidence_parent.mkdir()
            hidden = evidence_parent / "hidden-rubric.json"
            hidden.write_text("rubric")
            outside = root / "outside"
            outside.write_text("unchanged")
            originals = [
                ROOT / "benchmarks/agent-task-comparison-v1/manifest.json",
                pilot.original_repository_root()
                / "benchmarks/agent-task-comparison-v1/manifest.json",
                hidden,
            ]
            stub = root / "opencode-stub"
            stub.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, shutil, subprocess, sys\n"
                "from pathlib import Path\n"
                f"protected={list(map(str, originals))!r}\n"
                f"outside=Path({str(outside)!r})\n"
                "args=sys.argv[1:]\n"
                "phase=args[0]\n"
                "assert phase in ('run','export')\n"
                "assert '--pure' in args\n"
                "assert 'PILOT_TEST_SECRET' not in os.environ\n"
                "config=Path(os.environ['OPENCODE_CONFIG'])\n"
                "assert config.is_absolute() and config.is_file()\n"
                "assert json.loads(config.read_text())['agent']\n"
                "assert Path(os.environ['HOME']).parent == config.parent\n"
                "assert all(Path(os.environ[x]).parent == config.parent for x in ('XDG_CONFIG_HOME','XDG_DATA_HOME','XDG_CACHE_HOME','TMPDIR'))\n"
                "compiler=shutil.which('semaprax')\n"
                "assert compiler and Path(compiler).parent == config.parent/'bin'\n"
                "mcp_command=json.loads(config.read_text())['mcp']['semaprax']['command']\n"
                "assert Path(mcp_command[2]) == Path(compiler), 'MCP must run the gateway executable, never its log'\n"
                "rpc=json.dumps({'jsonrpc':'2.0','id':1,'method':'tools/list'})+'\\n'\n"
                "probe=subprocess.run(mcp_command,input=rpc,text=True,capture_output=True,timeout=5)\n"
                "assert probe.returncode == 0 and json.loads(probe.stdout)['result']['tools'][0]['name'] == 'command'\n"
                "rpc=json.dumps({'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':'command','arguments':{'argv':['--version']}}})+'\\n'\n"
                "probe=subprocess.run(mcp_command,input=rpc,text=True,capture_output=True,timeout=5)\n"
                "result=json.loads(probe.stdout)['result']\n"
                "assert probe.returncode == 0 and not result['isError'], result\n"
                "for item in protected:\n"
                "    try: Path(item).read_bytes()\n"
                "    except OSError: pass\n"
                "    else: raise SystemExit('protected read succeeded: '+item)\n"
                "try: outside.write_text('escaped')\n"
                "except OSError: pass\n"
                "else: raise SystemExit('outside write succeeded')\n"
                "if phase == 'run':\n"
                f"    assert args[args.index('--model')+1] == {pilot.MODEL!r}\n"
                "    candidate=Path(args[args.index('--dir')+1])\n"
                "    assert (candidate/'semaprax.toml').is_file()\n"
                "    (candidate/'agent-proof').write_text('run was confined')\n"
                "    print(json.dumps({'sessionID':'stub-session','boundary':'enforced'}))\n"
                "else:\n"
                "    assert args[1] == 'stub-session'\n"
                "    (config.parent/'export-proof').write_text('export was confined')\n"
                "    print(json.dumps({'phase':'export','boundary':'enforced'}))\n"
            )
            stub.chmod(0o700)
            with mock.patch.dict(os.environ, {"PILOT_TEST_SECRET": "must-not-pass"}):
                compiler_source = root / "compiler-stub"
                compiler_source.write_text("#!/usr/bin/python3\nprint('compiler stub')\n")
                compiler_source.chmod(0o700)
                compiler_before = compiler_source.read_bytes()
                records = {
                    lane: pilot.run_tuple(
                        "signature-migration-v1", lane, 1, stub,
                        str(compiler_source), evidence_parent / lane, 10,
                    )
                    for lane in ("semaprax-source-first", "semaprax-graph-operational")
                }
            record = records["semaprax-source-first"]
            evidence = evidence_parent / "semaprax-source-first"
            self.assertEqual(compiler_source.read_bytes(), compiler_before)
            self.assertEqual(record["semaprax_sha256"], pilot.sha(compiler_before))
            self.assertEqual(record["status"], "ineligible")
            self.assertEqual(outside.read_text(), "unchanged")
            self.assertEqual(
                json.loads((evidence / "stdout.jsonl").read_text())["boundary"],
                "enforced",
            )
            self.assertEqual(
                json.loads((evidence / "session.json").read_text()),
                {"phase": "export", "boundary": "enforced"},
            )
            self.assertIn("agent-proof", record["after"])
            self.assertNotIn("agent-proof", record["before"])
            self.assertIn("subpath", (evidence / "seatbelt.sb").read_text())
            self.assertEqual(
                record["stdout_sha256"],
                pilot.sha((evidence / "stdout.jsonl").read_bytes()),
            )
            for lane, lane_record in records.items():
                lane_evidence = evidence_parent / lane
                self.assertEqual(lane_record["status"], "ineligible")
                self.assertTrue((lane_evidence / "candidate-source.json").is_file())
                self.assertTrue((lane_evidence / "mcp-wire.jsonl").is_file())


if __name__ == "__main__":
    unittest.main()
