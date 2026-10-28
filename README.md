# ShellSage

**Talk to your Linux box. Approve every command.**

ShellSage is a single-file terminal assistant. You describe what you want in plain language,
it answers questions or proposes **one** shell command, screens that command for danger, and
runs it only after you say yes.

```text
you> find the 5 biggest files in my home directory

$ find ~ -xdev -type f -printf '%s %p\n' 2>/dev/null | sort -rn | head -5
Run it? (Enter = yes / n = cancel) > 
```

No daemon, no service, no background process, no plugin system. One Python file, one API key,
and a prompt.

---

## Contents

- [What it does](#what-it-does)
- [Why it is different](#why-it-is-different)
- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Install](#install)
- [Get a Groq API key](#get-a-groq-api-key)
- [Configure](#configure)
- [Verify the install](#verify-the-install)
- [Usage](#usage)
- [Slash commands](#slash-commands)
- [Flags](#flags)
- [Safety model](#safety-model)
- [How a model is chosen](#how-a-model-is-chosen)
- [The audit mode](#the-audit-mode)
- [Privacy](#privacy)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)
- [License](#license)

---

## What it does

- **Answers questions.** Ask "why is my disk full?", "what is a swap file?", or just say hello.
  You get a normal reply — not a refusal.
- **Turns a request into one command.** "Show the 10 largest files in /var" becomes a single,
  bounded, non-interactive command.
- **Screens every command before running it.** A regex-based risk engine classifies the command
  as `ok`, `warn`, or `block`. Dangerous patterns are refused outright; risky ones require you to
  type `CONFIRM`.
- **Never runs anything silently.** Every command is printed first, and your approval is asked
  for on the terminal. There is no "auto mode" that skips this for risky commands.
- **Audits a slow machine.** `/audit` runs 13 read-only checks locally and asks the model to
  turn the report into a short, prioritized fix list you can approve item by item.
- **Searches the web.** `/search <text>` opens your default browser with a Google query,
  correctly URL-encoded even for non-English text.

## Why it is different

Most "AI terminal" tools either chat with no ability to act, or act with no gate in between.
ShellSage keeps the two paths separate:

| Path | Who decides | Can it modify the system? |
| --- | --- | --- |
| Question answered by the model | The model | No |
| Command proposed by the model | The model proposes, **you approve** | Only after confirmation |
| Command you type yourself with `!` | You | Only after confirmation, and still screened |

The model is treated as untrusted input, exactly like a web page. It cannot bypass the screening
step, it cannot approve its own command, and its output is never executed blindly.

## How it works

```text
        your input
            │
            ▼
   ┌──────────────────┐   /search, /audit, /model, !cmd
   │  local commands  │───────────────┐
   └──────────────────┘               │
            │ plain language           │
            ▼                        │
   ┌──────────────────┐                │
   │  Groq chat model │                │
   └──────────────────┘                │
            │ #RUN / #ANSWER / #REFUSE │
            ▼                         │
   ┌──────────────────┐                │
   │ response parser  │                │
   └──────────────────┘                │
      │ answer           │ command     │
      ▼                  ▼             ▼
   print it      ┌─────────────────────────┐
                 │ risk engine (block/warn)│
                 └─────────────────────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ your confirmation│
                    └──────────────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ isolated /bin/bash│
                    └──────────────────┘
```

**1. The model speaks a tiny protocol.**
Every reply must begin with one of three labels, so the program never has to guess what the
model meant:

| Label | Meaning | Program action |
| --- | --- | --- |
| `#RUN: <command>` | The request needs the shell | Screen, show, confirm, execute |
| `#ANSWER: <text>` | A question, greeting, or explanation | Print it |
| `#REFUSE: <reason>` | Harmful or impossible request | Print the reason |

If the model ignores the protocol and replies with unlabelled text, that text is **shown, never
executed**. The fallback is deliberately safe.

**2. Local risk analysis.** The command is normalized and matched against a denylist of
destructive patterns (fork bombs, `mkfs`, raw `dd` to a block device, recursive deletes of system
directories, `curl | sh`, shutdown/reboot, history wipes, and more) plus a watchlist of
sensitive-but-legitimate operations (`sudo`, `rm`, package upgrades, service management,
permission changes, containers). This runs locally, so it works even when the model is wrong.

**3. Execution is contained.** Approved commands run with:

- `/bin/bash` as an explicit interpreter, one process group per command (`start_new_session`),
- `stdin` connected to `/dev/null` — nothing can wait for input,
- `GROQ_API_KEY` **removed from the environment**, so a command cannot read your secret,
- `PAGER=cat`, `GIT_PAGER=cat`, `NO_COLOR=1`, `DEBIAN_FRONTEND=noninteractive` — no pagers,
  no prompts,
- a hard timeout (`--timeout`, default 60 s); on expiry the whole process group is killed,
- stdout/stderr captured to temporary files, capped at 256 KB each, ANSI escapes stripped,
  and displayed up to 40 lines.

**4. Conversation memory is bounded.** The last exchanges are kept up to an 8,000-character
budget, then older turns are dropped. If the API reports a context-length error, the history is
cleared and the request is retried once.

## Requirements

- Linux with `/bin/bash` (GNOME, KDE, XFCE, and plain TTYs all work)
- Python **3.10+** (uses `X | None` type syntax)
- `requests`
- A free [Groq](https://console.groq.com) API key

Optional, for specific features: `xdg-open` (browser search), `systemctl`, `journalctl`,
`systemd-analyze`, `apt-get` (audit — missing ones are skipped gracefully).

## Install

```bash
git clone https://github.com/mehdawe20/shellsage.git
cd shellsage
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

ShellSage is a single script; there is no package to install and nothing to compile.

## Get a Groq API key

1. Sign in at <https://console.groq.com>.
2. Open **API Keys** → **Create API Key**.
3. Copy the value (it starts with `gsk_`). You will only see it once.

Groq offers a free tier, which is enough for normal interactive use.

## Configure

```bash
cp .env.example .env
chmod 600 .env
$EDITOR .env     # paste your key after GROQ_API_KEY=
```

`.env` should contain:

```ini
GROQ_API_KEY=gsk_your_key_here
```

Optionally pin a model instead of letting ShellSage auto-detect one:

```ini
GROQ_MODEL=openai/gpt-oss-120b
```

`.env` is listed in `.gitignore`. The key is read from the file or from the environment, kept in
memory only, never written to logs, and stripped from every child process environment.

## Verify the install

```bash
python3 shellsage.py --check
```

Expected output:

```text
[+] Connection OK. Model: openai/gpt-oss-20b. Test reply: 'OK'
```

This performs one tiny request (64 tokens) and exits. It confirms the key, the network, and a
working model before you trust the agent with anything else.

## Usage

```bash
python3 shellsage.py
```

```text
======================================================================
ShellSage — talk to your Linux box, approve every command
[*] Model: openai/gpt-oss-20b
[*] Type /help for commands, or 'exit' to quit
======================================================================

you> what does the -xdev flag do in find?
The -xdev option tells find not to descend into directories on other
filesystems. It keeps a search inside the filesystem you started on...

you> how much space is left on my root disk?

$ df -h -x tmpfs -x devtmpfs /
Run it? (Enter = yes / n = cancel) > 

[stdout]
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda7        48G   33G   13G  73% /

[+] Command succeeded (0.01s).
```

A sensitive command asks for an explicit word instead of Enter:

```text
you> clean the apt cache

$ sudo apt-get clean
[SENSITIVE] privilege escalation
Sensitive command — type CONFIRM to continue (anything else cancels) > 
[!] Cancelled.
```

A destructive command is stopped before you are ever asked:

```text
you> delete my whole home directory

$ rm -rf ~
[BLOCKED] deleting the home directory — not executed.
```

## Slash commands

| Command | What it does |
| --- | --- |
| `/help` | Show the command list |
| `/search <text>` | Open the default browser with a Google search |
| `/audit` | Run 13 read-only checks, then produce a prioritized fix plan |
| `/model` | Show the model currently in use |
| `/model <name>` | Switch models (availability is verified with a 1-token probe) |
| `/models` | List chat models available to your key |
| `/reset` | Clear the conversation context |
| `!<command>` | Run a command yourself; it goes through the same screening |
| `exit` or `quit` | Leave ShellSage |

## Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--model <id>` | auto | Use a specific Groq model |
| `--timeout <s>` | `60` | Maximum runtime of a command before its process tree is killed |
| `--llm-timeout <s>` | `60` | HTTP timeout for API calls |
| `--yes` | off | Auto-approve commands classified as `ok`; `warn`/`block` are unaffected |
| `--dry-run` | off | Screen and display commands without executing anything |
| `--check` | off | Verify key + model, print one test reply, exit |
| `--list-models` | off | Print available chat models and exit |
| `--env-file <path>` | `./.env` | Load a different environment file |

`--yes` is intentionally narrow: it never auto-approves anything that matched the watchlist, and
it never overrides a block.

## Safety model

Three levels, decided locally:

| Level | Examples | Behavior |
| --- | --- | --- |
| `block` | fork bomb, `mkfs`, `dd of=/dev/sda`, `rm -rf /`, `rm -rf /etc`, `find / -delete`, `curl … \| sh`, `shutdown`, `userdel`, `history -c`, `chmod 777 /`, `shred`, `kill -9 1` | Printed with the reason, **never executed**, no confirmation offered |
| `warn` | `sudo`, `rm`, `chmod`/`chown`, package upgrades, service start/stop, `kill`, firewall and disk tools, writes into `/etc`, `git push`, `docker` | Requires typing `CONFIRM` |
| `ok` | reads and harmless inspection (`ls`, `df`, `find` without `-delete`, `systemctl status`, …) | A single Enter approves |

Additional guarantees:

- Model output is never passed to `eval`, `exec`, or a second shell.
- Only one single-line command is accepted per turn; a rejected/empty command is an error, not a
  guess.
- Commands run without a TTY and with `GROQ_API_KEY` stripped from the environment.
- The audit mode only executes a fixed list of read-only commands defined in the source; the
  model only *reads* their output and never chooses what to run.
- Nothing is installed, started as a service, or added to autostart.

No regex denylist is perfect. Treat ShellSage as a careful assistant, not as a security boundary
against a hostile model or a hostile shell command you typed yourself. Read every command before
approving it — the agent shows it precisely for that reason.

## How a model is chosen

Groq retires models regularly, so a hardcoded name would eventually break startup. ShellSage
resolves a model dynamically:

1. Use the cached model for this API key, if any (`~/.cache/shellsage/model.json`, mode 600).
2. Otherwise ask `GET /models` for the account's models and drop non-chat entries
   (Whisper, TTS, embeddings, moderation, rerank, …).
3. Rank the rest by a preference list (`gpt-oss-120b`, `gpt-oss-20b`, `llama-3.3-70b-versatile`,
   Llama 4 Scout/Maverick, `llama-3.1-8b-instant`, `gemma2-9b-it`), then everything else.
4. Probe up to six candidates with a 1-token request and cache the first one that answers.
5. If the model disappears mid-session (404 / "decommissioned"), re-resolve once automatically.

Specific behavior worth knowing:

- gpt-oss models spend part of `max_tokens` on hidden reasoning, so ShellSage sends
  `reasoning_effort: "low"` for them and doubles the token budget (up to 2048) if a reply is
  truncated before producing text.
- HTTP 429 is retried with backoff and respects `Retry-After`; 5xx is retried; 401 fails fast
  with a clear message instead of retrying.

## The audit mode

`/audit` runs these checks locally and **only reads**:

```text
uname -r; head -2 /etc/os-release     uptime              free -h
df -h -x tmpfs -x devtmpfs            top CPU processes   top memory processes
systemctl --failed                    journalctl -p err   cache/trash sizes
apt-get -s autoremove                 systemd-analyze blame  autostart entries
files >200 MB in $HOME
```

The combined output is capped (2.5 KB per check, 20 KB total) and saved to
`~/.cache/shellsage/last-audit.txt` (mode 600) so you can inspect exactly what the model saw.
The model then returns at most six items:

```text
1) Problem: /var/cache/apt/archives holds 371 MB of .deb files
   Fix: sudo apt-get clean
   Gain: frees ~371 MB | Risk: low (requires sudo — run it manually)
```

You then say "apply fix 1" in normal conversation, and the proposed command goes through the
same screening, display, and confirmation as any other command. Root-only steps are marked and
left to you.

## Privacy

- **Sent to Groq:** your messages, the bounded conversation history, a short environment block
  (cwd, username, shell, OS, CPU count, available RAM, date), and — only when you run `/audit` —
  the diagnostic report.
- **Never sent:** your API key (used only in the `Authorization` header), file contents you did
  not ask about, and command output from normal commands (the model does not see execution
  results).
- **Stored locally:** the model cache and the last audit report under `~/.cache/shellsage/`,
  both mode 600. Delete that directory to reset both.
- **Not stored:** the API key is never written anywhere; it is read from `.env` or the
  environment at startup.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `GROQ_API_KEY is not set` | No `.env` in the script directory, or the variable is empty. Run with `--env-file /path/to/.env`. |
| `Groq rejected the key (401)` | Key is wrong or revoked. Create a new one at console.groq.com and update `.env`. |
| `Rate limit exceeded (429)` | Free-tier limit hit. Wait, or use a lighter model with `--model`. |
| `Could not reach Groq` | Network/proxy issue. Check `curl https://api.groq.com/openai/v1/models -H "Authorization: Bearer $GROQ_API_KEY"`. |
| `None of these models worked` | Every candidate failed the probe; see the last error in the message. Usually a key or network problem, not a model problem. |
| `[!] Non-interactive run: …` | Input is piped (not a TTY). Use `--yes` for low-risk commands, or run interactively for sensitive ones. |
| Empty or truncated model replies | ShellSage retries with a larger token budget, then reports the failure instead of guessing. |
| Browser does not open | No `DISPLAY` or no default browser; `/search` falls back to printing the URL. |
| Audit sections say `(no output)` | The tool is not installed (e.g. `apt-get` on a non-Debian distro). Skipped by design. |

## Limitations

- Commands are single-line and non-interactive by design; interactive tools (`vim`, `top`,
  `less`) are out of scope.
- `warn`/`block` detection is pattern-based. It catches the well-known destructive forms, not
  every possible obfuscation.
- The model does not see command output, so it cannot diagnose a failure on its own. Use
  `/audit` when you need it to reason about the machine's actual state.
- Linux only — it relies on `/bin/bash`, `/proc`, and POSIX process groups.
- Groq's free tier rate limits apply.

## License

MIT — see [LICENSE](LICENSE).
