"""Client-origin before/after acceptance around a single SSH deployment."""

import json
from pathlib import Path
from .deploy import acceptance_decision
from .remote import execute
from .util import Error, atomic
from .verification import verify


def remote_apply(a, cases):
    if not a.verify_output or len(cases.get("targets", [])) < 2:
        raise Error("SSH acceptance requires --verify-output and two independent HTTPS targets")
    out = Path(a.verify_output)
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    before = verify(cases, out / "before.jsonl")
    args = [a.command]
    if a.command == "upgrade":
        args += ["--component", a.component, "--to", a.to]
    try:
        result = execute(a.host, args, jump=a.jump, config=a.config, secrets=a.secrets, lock=a.lock)
        deployment = json.loads(result)
    except BaseException:
        atomic(
            out / "decision.json", {"decision": "remote_outcome_unknown_or_failed", "retry": False}
        )
        raise
    after = verify(cases, out / "after.jsonl")
    verdict = acceptance_decision(before, after)
    if verdict["decision"] == "rollback":
        if deployment.get("changed"):
            atomic(out / "decision.json", verdict)
            execute(a.host, ["rollback"], jump=a.jump)
            restored = verify(cases, out / "restored.jsonl")
            verdict["restored_passed"] = restored["all_declared_passed"]
        else:
            verdict["decision"] = "undetermined_external_failure"
    atomic(out / "decision.json", verdict)
    return {"deployment": deployment, "acceptance": verdict}
