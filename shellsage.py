#!/usr/bin/env python3
"""ShellSage — a terminal assistant that answers questions and runs the Linux commands you approve."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import platform
import random
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urlencode

import requests

API_BASE = "https://api.groq.com/openai/v1"
CACHE_FILE = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "shellsage" / "model.json"
AUDIT_REPORT_FILE = CACHE_FILE.parent / "last-audit.txt"

HISTORY_CHAR_BUDGET = 8000
OUTPUT_BYTE_LIMIT = 256 * 1024
DEFAULT_LLM_TIMEOUT = 60
DEFAULT_EXEC_TIMEOUT = 60
MAX_TOKENS = 512

# Groq decommissions models regularly, so this is only a preference order.
# Anything missing from the account is skipped automatically.
PREFERRED_MODELS = (
    "openai/gpt-oss-120b",
    "openai/gpt-oss-20b",
    "llama-3.3-70b-versatile",
    "meta-llama/llama-4-scout-17b-16e-instruct",
    "meta-llama/llama-4-maverick-17b-128e-instruct",
    "llama-3.1-8b-instant",
    "gemma2-9b-it",
)
NON_CHAT_MARKERS = ("whisper", "tts", "guard", "embed", "moderation", "rerank", "orpheus", "vision-preview")

SYSTEM_PROMPT_TEMPLATE = """# ROLE
You are a Linux assistant that can either run shell commands or talk to the operator.
The operator may write in any language, so always answer in the same language they used.

# RESPONSE PROTOCOL
Every reply must start with exactly one of these prefixes:
1. `#RUN: <command>` — the request needs the shell. Exactly ONE single-line, non-interactive Bash command.
2. `#ANSWER: <text>` — greetings, questions, explanations, capability questions, or chit-chat.
   Write naturally in the operator's language; multiple lines are allowed.
3. `#REFUSE: <reason>` — ONLY for genuinely harmful or destructive requests, or when the request truly cannot be helped.

# RULES
- Greetings ("hello", "hi"), "why?", "what can you do?", and general questions are NOT refusals: use `#ANSWER`.
- Never output a bare command without the `#RUN` prefix, and never wrap output in markdown code fences.
- Join dependent shell steps with `&&` (never `;`).
- For multi-item tasks (for example "create 10 files"), write every item out explicitly and repeat the
  operation once per item, chained with `&&`. NEVER use `for`/`while` loops or brace expansion:
  they hide the actual items and often miss some.
- Count the requested items before answering and make sure the command creates exactly that many.
- Make each file's content specific to its item (2-3 short sentences), never one generic sentence reused.
- When creating files, end the command with `&& ls -1 <target_dir>` so the operator can verify the result.
- Shell commands must be non-interactive and finish quickly: use `-y`, `--no-pager`, `head`, `timeout 30`.
- To open the browser or search the web use: `#RUN: xdg-open 'https://www.google.com/search?q=<query>'`
  The query may be written in raw non-English text; the agent URL-encodes it before running.
- Opening a browser with `xdg-open` is allowed. Starting GUI apps or waiting for human interaction is not.
- Never use `sudo`/`su`, interactive programs (vim, nano, less, more, top, htop, watch, man),
  long-running services, or reboot/power off.
- Never delete or overwrite data (rm, dd, mkfs, chmod -R, chown -R, redirection into /etc)
  unless the operator explicitly asked for that exact destructive action.
- Never pipe remote scripts into a shell.
- Keep shell output small: filter with grep/head/awk; never dump full logs.
- You do not see command output, so do not assume a previous command succeeded.

# ENVIRONMENT
Low-end host (2 cores, ~4 GB RAM). Prefer light tools and bounded output.

{{ENV}}
"""


class AgentError(RuntimeError):
    pass


class AuthError(AgentError):
    pass


class ContextError(AgentError):
    pass


@dataclass(frozen=True)
class Verdict:
    level: str  # ok | warn | block
    reason: str = ""


@dataclass(frozen=True)
class Decision:
    kind: str  # run | answer | refuse | error
    text: str


@dataclass(frozen=True)
class ExecResult:
    code: int
    stdout: str
    stderr: str
    timed_out: bool
    stdout_truncated: bool
    stderr_truncated: bool


def load_dotenv(path: Path) -> None:
    if not path.is_file():
        return
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            os.environ.setdefault(key, value)


def _mem_available_gb() -> float | None:
    try:
        with open("/proc/meminfo", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) / 1024 / 1024
    except (OSError, ValueError, IndexError):
        return None
    return None


def build_system_prompt() -> str:
    info = [
        f"- cwd: {os.getcwd()}",
        f"- user: {getpass.getuser()}",
        f"- shell: {os.environ.get('SHELL', '/bin/bash')}",
        f"- os: {platform.platform()}",
        f"- cpu threads: {os.cpu_count()}",
    ]
    mem = _mem_available_gb()
    if mem is not None:
        info.append(f"- available RAM: {mem:.1f} GB")
    info.append(f"- date: {time.strftime('%Y-%m-%d')}")
    return SYSTEM_PROMPT_TEMPLATE.replace("{{ENV}}", "\n".join(info))


def _api_error(resp: requests.Response) -> str:
    try:
        data = resp.json()
    except ValueError:
        return resp.text[:300].strip() or resp.reason
    err = data.get("error")
    if isinstance(err, dict):
        return str(err.get("message") or err)
    return str(err or data)[:300]


def _retry_after(resp: requests.Response | None, attempt: int) -> float:
    if resp is not None:
        raw = resp.headers.get("retry-after")
        if raw:
            try:
                return min(max(float(raw), 0.5), 30.0)
            except ValueError:
                pass
    return min(2.0 * attempt + random.random(), 15.0)


_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean_text(text: str) -> str:
    return _ANSI_RE.sub("", text)


# --- risk analysis ---------------------------------------------------------

_CMD_START = r"(?:^|[;&|]\s*)\s*(?:sudo\s+)?"
_RM_RECURSIVE = r"\brm\b(?=[^;&|]*\s-{1,2}[a-zA-Z-]*[rR])"

BLOCK_RULES: tuple[tuple[str, str], ...] = (
    (r":\s*\(\s*\)\s*\{[^}]*:\s*\|\s*:[^}]*\}", "fork bomb"),
    (_CMD_START + r"mkfs(?:\.[a-z0-9]+)?\b", "formatting/erasing a filesystem"),
    (_CMD_START + r"dd\b[^;&|]*\bof\s*=\s*/dev/(sd|hd|vd|nvme|mmcblk|disk)", "raw write to a disk device"),
    (r">\s*/dev/(sd|hd|vd|nvme|mmcblk|disk)", "raw write to a disk device"),
    (_RM_RECURSIVE + r"[^;&|]*\s+/(?:\*|\s|$)", "deleting the filesystem root"),
    (
        _RM_RECURSIVE
        + r"[^;&|]*\s+/(?:bin|boot|dev|etc|home|lib|lib64|opt|proc|root|sbin|srv|sys|usr|var)(?:/[^/\s]+){0,1}/?\*?(?:\s|$)",
        "deleting a system directory",
    ),
    (_RM_RECURSIVE + r"[^;&|]*\s+(?:~|\$home)(?:/\*?)?(?:\s|$)", "deleting the home directory"),
    (r"\brm\b[^;&|]*\s+/(?:etc/(?:passwd|shadow|sudoers|fstab|hosts)|boot/)\S*", "deleting critical system files"),
    (_CMD_START + r"find\s+/\s[^|;]*-delete\b", "recursive delete via find"),
    (_CMD_START + r"find\s+/\s[^|;]*-exec\s+rm\b", "recursive delete via find"),
    (_CMD_START + r"(?:curl|wget)\b[^;&|]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b", "piping a remote script into a shell"),
    (_CMD_START + r"(?:shutdown|reboot|poweroff|halt)\b", "shutdown/reboot"),
    (_CMD_START + r"(?:init|telinit)\s+[06]\b", "shutdown/reboot"),
    (_CMD_START + r"systemctl\s+(?:poweroff|reboot|halt|suspend|hibernate|kexec)\b", "shutdown/reboot"),
    (_CMD_START + r"(?:userdel|groupdel|chpasswd)\b", "modifying user accounts"),
    (_CMD_START + r"crontab\s+-r\b", "wiping cron jobs"),
    (_CMD_START + r"history\s+-c\b", "wiping shell history"),
    (_CMD_START + r"chmod\s+(?:-[a-z-]+\s+)*(?:777|666)\s+/(?=\s|$|[;&|])", "world-writable root"),
    (_CMD_START + r"chown\s+-[a-z]*r[a-z]*\s+\S+\s+/(?=\s|$|[;&|])", "recursive chown on root"),
    (_CMD_START + r"(?:shred|wipefs|blkdiscard)\b", "irreversible data destruction"),
    (_CMD_START + r"kill\s+-9\s+1\b", "killing PID 1"),
    (r"\b(?:mv|rm)\b[^;&|]*\s+/\*", "wiping root contents"),
)

WARN_RULES: tuple[tuple[str, str], ...] = (
    (r"\bsudo\b|\bdoas\b|\bsu\s+-", "privilege escalation"),
    (_CMD_START + r"""xdg-open\s+(?!["']?https?://)""", "opens a non-web target"),
    (r"\brm\b", "deletes files"),
    (r"\b(?:chmod|chown|chattr|setfacl)\b", "changes permissions/ownership"),
    (r"\bfind\b[^;&|]*-delete\b", "delete via find"),
    (
        r"\b(?:apt|apt-get|dpkg|snap|flatpak|pacman|dnf|yum)\b[^;&|]*"
        r"\b(?:remove|purge|autoremove|dist-upgrade|full-upgrade|upgrade)\b",
        "system package changes",
    ),
    (r"\b(?:pip|pip3|npm|gem)\b[^;&|]*\b(?:uninstall|install)\b", "installs/removes packages"),
    (r"\bsystemctl\s+(?:start|stop|restart|reload|enable|disable|mask|unmask)\b|\bservice\s+\S+\s+(?:start|stop|restart)\b", "service management"),
    (r"\b(?:kill|pkill|killall)\b", "kills processes"),
    (r"\b(?:iptables|nft|ufw|firewall-cmd)\b", "firewall changes"),
    (r"\b(?:mount|umount|fdisk|parted|gdisk|losetup|swapon|swapoff)\b", "disk/partition changes"),
    (r"\b(?:crontab|systemd-run|at)\b", "schedules jobs"),
    (r"\b(?:eval|exec)\b|\b(?:ba|z|da|k)?sh\s+-c\b", "dynamic execution"),
    (r">\s*/(?:etc|boot|usr|bin|sbin|lib)/", "writes into system paths"),
    (r"\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b", "pipes output into a shell"),
    (r"\b(?:git\s+push|docker|podman|kubectl)\b", "deployment/container operations"),
    (r"\b(?:truncate|dd)\b", "direct write/truncate"),
)


def analyze(command: str) -> Verdict:
    normalized = " ".join(command.lower().split())
    for pattern, reason in BLOCK_RULES:
        if re.search(pattern, normalized):
            return Verdict("block", reason)
    try:
        if not shlex.split(command):
            return Verdict("warn", "empty or unparseable command")
    except ValueError:
        return Verdict("warn", "unbalanced quotes")
    for pattern, reason in WARN_RULES:
        if re.search(pattern, normalized):
            return Verdict("warn", reason)
    return Verdict("ok")


# --- Groq client -----------------------------------------------------------


class GroqClient:
    def __init__(self, api_key: str, model: str | None = None, timeout: int = DEFAULT_LLM_TIMEOUT):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "shellsage/1.0",
            }
        )
        self._model = model
        self._fingerprint = hashlib.sha256(api_key.encode()).hexdigest()[:12]

    @property
    def model(self) -> str:
        if not self._model:
            self._model = self._resolve_model()
        return self._model

    def set_model(self, name: str) -> None:
        name = name.strip()
        if not name:
            raise AgentError("The model name is empty.")
        status, detail = self._probe(name)
        if status == 401:
            raise AuthError("Groq rejected the key (401). Check GROQ_API_KEY.")
        if status != 200:
            raise AgentError(f"Model '{name}' is unavailable ({status}: {detail})")
        self._model = name
        self._save_cache(name)

    def available_models(self) -> list[str]:
        return self._rank_models(self._list_models())

    def _probe(self, name: str) -> tuple[int | None, str]:
        try:
            resp = self.session.post(
                f"{API_BASE}/chat/completions",
                json={
                    "model": name,
                    "messages": [{"role": "user", "content": "ping"}],
                    "max_tokens": 1,
                    "temperature": 0,
                },
                timeout=min(self.timeout, 15),
            )
        except requests.RequestException as exc:
            return None, str(exc)
        if resp.status_code == 200:
            return 200, ""
        return resp.status_code, _api_error(resp)

    def _list_models(self) -> list[str]:
        last = "unknown"
        for attempt in range(2):
            try:
                resp = self.session.get(f"{API_BASE}/models", timeout=min(self.timeout, 20))
            except requests.RequestException as exc:
                last = str(exc)
                time.sleep(1.0 + attempt)
                continue
            if resp.status_code == 200:
                return [m.get("id", "") for m in resp.json().get("data", []) if m.get("id")]
            if resp.status_code == 401:
                raise AuthError("Groq rejected the key (401). Create a new key at console.groq.com.")
            last = f"{resp.status_code}: {_api_error(resp)}"
            time.sleep(1.0 + attempt)
        raise AgentError(f"Could not list models: {last}")

    @staticmethod
    def _rank_models(ids: list[str]) -> list[str]:
        usable = [i for i in ids if not any(marker in i.lower() for marker in NON_CHAT_MARKERS)]
        ranked = [m for m in PREFERRED_MODELS if m in usable]
        return ranked + [m for m in usable if m not in ranked]

    def _resolve_model(self) -> str:
        cached = self._load_cache()
        candidates: list[str] = [cached] if cached else []
        try:
            ranked = self._rank_models(self._list_models())
        except AuthError:
            raise
        except AgentError:
            if not candidates:
                raise
            ranked = []
        for name in ranked:
            if name not in candidates:
                candidates.append(name)
        if not candidates:
            raise AgentError("No chat models are available on this account.")

        candidates = candidates[:6]
        probed = 0
        net_fail = 0
        last_detail = ""
        for name in candidates:
            probed += 1
            status, detail = self._probe(name)
            if status == 200:
                self._save_cache(name)
                return name
            if status == 401:
                raise AuthError("Groq rejected the key (401). Check GROQ_API_KEY.")
            if status == 429:
                raise AgentError("Rate limit exceeded (429). Wait a moment and try again.")
            if status is None:
                net_fail += 1
            last_detail = detail
        if probed and net_fail == probed:
            raise AgentError(f"Could not reach Groq. Check your network/proxy: {last_detail}")
        raise AgentError(
            "None of these models worked: "
            + ", ".join(candidates)
            + (f" (last error: {last_detail})" if last_detail else "")
        )

    def _load_cache(self) -> str | None:
        try:
            data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if data.get("fingerprint") != self._fingerprint:
            return None
        model = data.get("model")
        return model if isinstance(model, str) and model else None

    def _save_cache(self, model: str) -> None:
        try:
            CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            CACHE_FILE.write_text(
                json.dumps({"fingerprint": self._fingerprint, "model": model, "saved_at": int(time.time())}),
                encoding="utf-8",
            )
            CACHE_FILE.chmod(0o600)
        except OSError:
            pass

    def _clear_cache(self) -> None:
        try:
            CACHE_FILE.unlink()
        except OSError:
            pass

    def chat(self, messages: list[dict[str, str]], max_tokens: int = MAX_TOKENS) -> str:
        payload: dict[str, object] = {
            "messages": messages,
            "temperature": 0.0,
            "max_tokens": max_tokens,
            "stream": False,
        }
        attempts = 0
        rediscovered = False
        while attempts < 4:
            attempts += 1
            payload["model"] = self.model
            # gpt-oss models spend max_tokens on hidden reasoning first; keep it short
            # so the visible command is not truncated to nothing.
            if "gpt-oss" in self.model:
                payload["reasoning_effort"] = "low"
            try:
                resp = self.session.post(f"{API_BASE}/chat/completions", json=payload, timeout=self.timeout)
            except requests.RequestException as exc:
                if attempts >= 4:
                    raise AgentError(f"Could not reach Groq: {exc}") from exc
                time.sleep(_retry_after(None, attempts))
                continue

            if resp.status_code == 200:
                data = resp.json()
                choices = data.get("choices") or []
                if not choices:
                    raise AgentError("Groq returned an empty response (no choices).")
                choice = choices[0]
                message = choice.get("message") or {}
                content = (message.get("content") or "").strip()
                truncated = choice.get("finish_reason") == "length"
                if not content or truncated:
                    if attempts < 4 and int(payload["max_tokens"]) < 2048:
                        payload["max_tokens"] = min(int(payload["max_tokens"]) * 2, 2048)
                        continue
                    if truncated:
                        raise AgentError("The model response was cut off before the command completed.")
                    raise AgentError("The response ended before producing text (reasoning used the token budget).")
                return content

            detail = _api_error(resp)
            if resp.status_code == 401:
                raise AuthError("Groq rejected the key (401). Create a new key and update .env.")
            if resp.status_code == 404 or "decommissioned" in detail.lower():
                if rediscovered:
                    raise AgentError(f"The model is no longer available: {detail}")
                rediscovered = True
                self._model = None
                self._clear_cache()
                payload["model"] = self.model
                continue
            if resp.status_code == 400 and re.search(
                r"context|too (?:large|long)|reduce the length|maximum tokens", detail, re.I
            ):
                raise ContextError(detail)
            if resp.status_code == 429:
                if attempts >= 4:
                    raise AgentError("Rate limit exceeded (429) after several attempts.")
                time.sleep(_retry_after(resp, attempts))
                continue
            if 500 <= resp.status_code < 600:
                if attempts >= 4:
                    raise AgentError(f"Groq server error ({resp.status_code}): {detail}")
                time.sleep(_retry_after(resp, attempts))
                continue
            raise AgentError(f"Groq {resp.status_code}: {detail}")
        raise AgentError("Request failed after 4 attempts.")


# --- agent -----------------------------------------------------------------


def extract_command(text: str) -> str | None:
    body = text.strip()
    if body.startswith("```"):
        lines = body.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        body = "\n".join(lines)
    lines = [line.strip() for line in body.splitlines() if line.strip()]
    if not lines:
        return None
    command = lines[0].strip("`").strip()
    command = re.sub(r"^(?:\$|>|#)\s+", "", command)
    if not command or len(command) > 2000:
        return None
    if re.search(r"[\u0600-\u06FF]", command) and not re.search(r"[A-Za-z]", command):
        return None
    return command


def strip_fence(text: str) -> str:
    body = text.strip()
    if not body.startswith("```"):
        return body
    lines = body.splitlines()[1:]
    if lines and lines[-1].strip().startswith("```"):
        lines = lines[:-1]
    return "\n".join(lines).strip()


_PREFIX_RE = re.compile(r"^\s*(?:\*\*|`)?\s*#?\s*(RUN|ANSWER|REFUSE)\s*:\s*(?:\*\*|`)?\s*", re.I)


class Agent:
    def __init__(self, client: GroqClient, history_budget: int = HISTORY_CHAR_BUDGET):
        self.client = client
        self.history: list[dict[str, str]] = []
        self.history_budget = history_budget

    def reset(self) -> None:
        self.history.clear()

    def ask(self, order: str) -> Decision:
        user_msg = {"role": "user", "content": order}
        messages = [{"role": "system", "content": build_system_prompt()}, *self._trim(), user_msg]
        try:
            answer = self.client.chat(messages)
        except ContextError:
            self.history.clear()
            messages = [{"role": "system", "content": build_system_prompt()}, user_msg]
            answer = self.client.chat(messages)

        decision = self._parse(answer)
        if decision.kind in {"run", "answer", "refuse"}:
            self.history.extend([user_msg, {"role": "assistant", "content": answer}])
            self._enforce_budget()
        return decision

    @staticmethod
    def _parse(answer: str) -> Decision:
        text = strip_fence(clean_text(answer))
        if not text:
            return Decision("error", "Empty response from the model.")
        match = _PREFIX_RE.match(text)
        if match:
            kind = match.group(1).lower()
            body = text[match.end() :].strip()
            if kind == "refuse":
                return Decision("refuse", body or "The model refused the request.")
            if kind == "answer":
                return Decision("answer", body) if body else Decision("error", "Empty #ANSWER response.")
            command = extract_command(body)
            if not command:
                return Decision("error", "No valid command found after #RUN.")
            return Decision("run", command)
        # Protocol ignored: never execute unlabelled text, show it as a reply instead.
        return Decision("answer", text)

    def _trim(self) -> list[dict[str, str]]:
        kept: list[dict[str, str]] = []
        budget = self.history_budget
        for msg in reversed(self.history):
            size = len(msg.get("content", "")) + 16
            if size > budget:
                break
            budget -= size
            kept.append(msg)
        return list(reversed(kept))

    def _enforce_budget(self) -> None:
        total = sum(len(m.get("content", "")) + 16 for m in self.history)
        while total > self.history_budget and len(self.history) > 1:
            for _ in range(2):
                if not self.history:
                    break
                total -= len(self.history[0].get("content", "")) + 16
                self.history.pop(0)


# --- execution -------------------------------------------------------------


def _kill_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def _read_capped(handle) -> tuple[str, bool]:
    handle.seek(0)
    data = handle.read(OUTPUT_BYTE_LIMIT + 1)
    truncated = len(data) > OUTPUT_BYTE_LIMIT
    return data[:OUTPUT_BYTE_LIMIT].decode("utf-8", "replace"), truncated


def run_command(command: str, timeout: int) -> ExecResult:
    env = {key: value for key, value in os.environ.items() if key != "GROQ_API_KEY"}
    env.update(
        {
            "PAGER": "cat",
            "GIT_PAGER": "cat",
            "SYSTEMD_PAGER": "cat",
            "NO_COLOR": "1",
            "DEBIAN_FRONTEND": "noninteractive",
        }
    )
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        proc = subprocess.Popen(
            command,
            shell=True,
            executable="/bin/bash",
            stdin=subprocess.DEVNULL,
            stdout=out,
            stderr=err,
            env=env,
            start_new_session=True,
        )
        timed_out = False
        try:
            code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_group(proc)
            code = proc.wait()
        except BaseException:
            _kill_group(proc)
            proc.wait()
            raise
        stdout, out_trunc = _read_capped(out)
        stderr, err_trunc = _read_capped(err)
    return ExecResult(code, stdout, stderr, timed_out, out_trunc, err_trunc)


def _display(text: str, max_lines: int = 40) -> str:
    lines = text.rstrip().splitlines()
    if len(lines) <= max_lines:
        return "\n".join(lines)
    return "\n".join(lines[:max_lines]) + f"\n… (+{len(lines) - max_lines} more lines)"


_BROWSER_QUOTED_RE = re.compile(r"^xdg-open\s+(['\"])(https?://.+?)\1\s*$", re.I | re.S)
_BROWSER_BARE_RE = re.compile(r"^xdg-open\s+(https?://\S+)\s*$", re.I)


def normalize_command(command: str) -> str:
    """Percent-encode the URL of a plain xdg-open call (non-ASCII queries included)."""
    command = command.strip()
    match = _BROWSER_QUOTED_RE.match(command)
    if match:
        url = match.group(2)
    else:
        bare = _BROWSER_BARE_RE.match(command)
        if not bare:
            return command
        url = bare.group(1)
    encoded = quote(url, safe=":/?&=%#@,;~-._+!$()*[]")
    return f"xdg-open {shlex.quote(encoded)}"


def search_web(query: str) -> None:
    query = query.strip()
    if not query:
        print("[!] Usage: /search <query>")
        return
    url = "https://www.google.com/search?" + urlencode({"q": query})
    print(f"[*] Opening browser: {url}")
    try:
        opened = webbrowser.open(url, new=2)
    except Exception as exc:
        print(f"[-] Could not open a browser: {exc}")
        return
    if opened:
        print("[+] Request handed to the default browser.")
    else:
        print("[-] No default browser found. Make sure DISPLAY and xdg-open are available.")


# --- read-only system audit -------------------------------------------------

AUDIT_COMMANDS: tuple[tuple[str, str], ...] = (
    ("System", "uname -r && head -2 /etc/os-release"),
    ("Uptime and load", "uptime"),
    ("Memory", "free -h"),
    ("Disk usage", "df -h -x tmpfs -x devtmpfs"),
    ("Top CPU processes", "ps -eo pid,comm,%cpu,%mem --sort=-%cpu | head -12"),
    ("Top memory processes", "ps -eo pid,comm,%cpu,%mem --sort=-%mem | head -12"),
    ("Failed services", "systemctl --failed --no-pager --no-legend | head -20"),
    ("System errors", "journalctl -p err -b -n 30 --no-pager 2>/dev/null | tail -30"),
    ("Cache and trash size", "du -sh ~/.cache ~/.local/share/Trash /var/cache/apt/archives 2>/dev/null"),
    ("Removable packages", "apt-get -s autoremove 2>/dev/null | tail -12"),
    ("Boot time", "systemd-analyze blame 2>/dev/null | head -10"),
    ("Autostart entries", "ls -1 ~/.config/autostart 2>/dev/null"),
    ("Large files in home", "find ~ -xdev -type f -size +200M -printf '%s %p\\n' 2>/dev/null | sort -rn | head -8"),
)

AUDIT_INSTRUCTIONS = """You are a Linux performance auditor for a low-end machine (2 cores, ~4 GB RAM).
You receive a READ-ONLY diagnostic report. Never invent data: base every finding on the report.

Reply with `#ANSWER:` followed by a prioritized plan in English, at most 6 items. Use exactly this shape:

1) Problem: <one line with the actual numbers or paths from the report>
   Fix: <one safe, non-interactive command>
   Gain: <expected improvement> | Risk: <low/medium/high>

Rules:
- Prefer non-destructive, reversible fixes: clear caches, remove autostart entries, vacuum user journals with a size limit, drop unused packages.
- Mark any command that needs root with "(requires sudo — run it manually)".
- Never suggest `sudo rm -rf`, deleting system directories, or disabling security services.
- If the machine is already healthy, say so and give at most 2 optional tweaks.
- Do not output `#RUN`; execute nothing.
"""

AUDIT_PER_COMMAND_LIMIT = 2500
AUDIT_TOTAL_LIMIT = 20000


def run_audit() -> str:
    sections: list[str] = []
    total = 0
    for title, command in AUDIT_COMMANDS:
        print(f"[*] Checking: {title}...")
        try:
            result = run_command(command, timeout=20)
        except Exception as exc:
            sections.append(f"## {title}\n(check failed: {exc})")
            continue
        body = clean_text(result.stdout).strip()
        if result.timed_out:
            body = "(timed out)"
        elif not body:
            body = "(no output)"
        body = body[:AUDIT_PER_COMMAND_LIMIT]
        section = f"## {title}\n$ {command}\n{body}"
        if total + len(section) > AUDIT_TOTAL_LIMIT:
            sections.append(f"## {title}\n(exceeded report budget — skipped)")
            continue
        total += len(section)
        sections.append(section)

    report = "\n\n".join(sections)
    try:
        AUDIT_REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
        AUDIT_REPORT_FILE.write_text(report + "\n", encoding="utf-8")
        AUDIT_REPORT_FILE.chmod(0o600)
        print(f"[*] Raw report saved to: {AUDIT_REPORT_FILE}")
    except OSError:
        pass
    return report


def audit_advice(client: GroqClient, report: str) -> str:
    messages = [
        {"role": "system", "content": AUDIT_INSTRUCTIONS},
        {"role": "user", "content": report},
    ]
    reply = clean_text(client.chat(messages, max_tokens=1200))
    body = strip_fence(reply)
    match = _PREFIX_RE.match(body)
    if match and match.group(1).lower() == "answer":
        body = body[match.end() :].strip()
    return body


class CommandRunner:
    def __init__(self, auto_yes: bool = False, dry_run: bool = False, timeout: int = DEFAULT_EXEC_TIMEOUT):
        self.auto_yes = auto_yes
        self.dry_run = dry_run
        self.timeout = timeout

    def run(self, command: str) -> None:
        command = normalize_command(clean_text(command))
        if not command:
            return
        verdict = analyze(command)

        print(f"\n$ {command}")
        if verdict.level == "block":
            print(f"[BLOCKED] {verdict.reason} — not executed.")
            return
        if verdict.level == "warn":
            print(f"[SENSITIVE] {verdict.reason}")
        if self.dry_run:
            print(f"[DRY RUN] level: {verdict.level} — nothing was executed.")
            return
        if not self._confirm(verdict):
            print("[!] Cancelled.")
            return

        print("[*] Running...")
        started = time.monotonic()
        try:
            result = run_command(command, self.timeout)
        except KeyboardInterrupt:
            print("\n[!] Command interrupted.")
            return
        elapsed = time.monotonic() - started

        if result.stdout:
            print(f"\n[stdout]\n{_display(clean_text(result.stdout))}")
            if result.stdout_truncated:
                print(f"… (stdout truncated at {OUTPUT_BYTE_LIMIT // 1024} KB)")
        if result.stderr:
            print(f"\n[stderr]\n{_display(clean_text(result.stderr))}")
            if result.stderr_truncated:
                print(f"… (stderr truncated at {OUTPUT_BYTE_LIMIT // 1024} KB)")

        if result.timed_out:
            print(f"[-] Timed out after {self.timeout}s; the process tree was killed.")
        elif result.code == 0:
            print(f"[+] Command succeeded ({elapsed:.2f}s).")
        else:
            print(f"[-] Command failed (exit {result.code}, {elapsed:.2f}s).")

    def _confirm(self, verdict: Verdict) -> bool:
        if verdict.level == "ok" and self.auto_yes:
            return True
        if not sys.stdin.isatty():
            if verdict.level == "ok":
                print("[!] Non-interactive run: add --yes to allow low-risk commands.")
            else:
                print("[!] Non-interactive run: sensitive commands need an interactive terminal.")
            return False
        if verdict.level == "warn":
            answer = input("Sensitive command — type CONFIRM to continue (anything else cancels) > ").strip()
            return answer == "CONFIRM"
        answer = input("Run it? (Enter = yes / n = cancel) > ").strip().lower()
        return answer not in {"n", "no"}


# --- CLI -------------------------------------------------------------------

HELP_TEXT = """Commands:
  /help            show this list
  /search <text>   open the browser and search Google
  /audit           read-only system check, then a fix plan you approve item by item
  /model           show the current model
  /model <name>    switch model (availability is verified first)
  /models          list chat models available on your account
  /reset           clear the conversation context
  !<command>       run a command manually (same safety screening)
  exit             quit ShellSage

You can also just ask a question or describe a task in plain language:
ShellSage answers questions, proposes one command when needed, and never
runs anything before you approve it."""


def repl(agent: Agent, runner: CommandRunner) -> None:
    print("=" * 70)
    print("ShellSage — talk to your Linux box, approve every command")
    print(f"[*] Model: {agent.client.model}")
    print("[*] Type /help for commands, or 'exit' to quit")
    print("=" * 70)

    while True:
        try:
            raw = input("\nyou> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            return
        if not raw:
            continue
        low = raw.lower()

        if low in {"exit", "quit", "/exit", "/quit"}:
            print("Goodbye.")
            return
        if low in {"help", "/help", "?"}:
            print(HELP_TEXT)
            continue
        if low == "/reset":
            agent.reset()
            print("[+] Conversation context cleared.")
            continue
        if low == "/search":
            print("[!] Usage: /search <query>")
            continue
        if low.startswith("/search "):
            search_web(raw.split(None, 1)[1])
            continue
        if low == "/audit":
            try:
                report = run_audit()
                print("[*] Analyzing the report...")
                print(f"\n{audit_advice(agent.client, report)}")
                print("\n[*] Pick an item (for example: 'apply fix 1') and you will be asked to confirm before anything runs.")
            except AgentError as exc:
                print(f"[-] {exc}")
            except KeyboardInterrupt:
                print("\n[!] Audit cancelled.")
            continue
        if low == "/models":
            try:
                for name in agent.client.available_models():
                    print(" -", name)
            except AgentError as exc:
                print(f"[-] {exc}")
            continue
        if low == "/model" or low.startswith("/model "):
            parts = raw.split(None, 1)
            if len(parts) == 1:
                print(f"[*] Current model: {agent.client.model}")
                continue
            try:
                agent.client.set_model(parts[1])
                print(f"[+] Switched to: {agent.client.model}")
            except AgentError as exc:
                print(f"[-] {exc}")
            continue
        if raw.startswith("!"):
            runner.run(raw[1:])
            continue

        try:
            decision = agent.ask(raw)
        except KeyboardInterrupt:
            print("\n[!] Request cancelled.")
            continue
        except AgentError as exc:
            print(f"[-] {exc}")
            continue

        if decision.kind == "run":
            runner.run(decision.text)
        elif decision.kind == "answer":
            print(f"\n{clean_text(decision.text)}")
        elif decision.kind == "refuse":
            print(f"[REFUSED] {decision.text}")
        else:
            print(f"[-] {decision.text}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ShellSage — a Groq-powered Linux terminal agent.")
    parser.add_argument("--model", help="Groq model id (default: auto-detect)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_EXEC_TIMEOUT, help="command timeout in seconds")
    parser.add_argument("--llm-timeout", type=int, default=DEFAULT_LLM_TIMEOUT, help="API timeout in seconds")
    parser.add_argument("--yes", action="store_true", help="auto-approve low-risk commands")
    parser.add_argument("--dry-run", action="store_true", help="show commands without executing")
    parser.add_argument("--check", action="store_true", help="verify API key + model, then exit")
    parser.add_argument("--list-models", action="store_true", help="list chat models and exit")
    parser.add_argument("--env-file", default=str(Path(__file__).with_name(".env")), help="path to .env file")
    args = parser.parse_args(argv)

    load_dotenv(Path(args.env_file).expanduser())

    api_key = os.environ.get("GROQ_API_KEY", "").strip()
    if not api_key:
        print("[-] GROQ_API_KEY is not set. Add it to .env or export it in your environment.")
        print("    Example: export GROQ_API_KEY='gsk_...'")
        return 2
    if not api_key.startswith("gsk_"):
        print("[!] Warning: the key does not start with gsk_ — make sure it is a Groq API key.")

    requested_model = args.model or os.environ.get("GROQ_MODEL") or None
    client = GroqClient(
        api_key,
        model=requested_model,
        timeout=args.llm_timeout,
    )

    try:
        if args.list_models:
            for name in client.available_models():
                print(name)
            return 0

        if requested_model:
            client.set_model(requested_model)

        model = client.model

        if args.check:
            reply = client.chat([{"role": "user", "content": "Reply with exactly: OK"}], max_tokens=64)
            print(f"[+] Connection OK. Model: {model}. Test reply: {reply!r}")
            return 0

    except AuthError as exc:
        print(f"[-] {exc}")
        return 3
    except AgentError as exc:
        print(f"[-] {exc}")
        return 4
    except KeyboardInterrupt:
        print("\n[!] Cancelled.")
        return 130

    runner = CommandRunner(auto_yes=args.yes, dry_run=args.dry_run, timeout=max(1, args.timeout))
    try:
        repl(Agent(client), runner)
    except AgentError as exc:
        print(f"[-] {exc}")
        return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())
