# IntentOS — A semantic execution layer for AI intent

[中文](README.md) | **English**

> Today an agent driving a machine works like this: say something → wait for a tool → say something again.
> IntentOS lets it **write the whole batch out at once** — as IR, essentially a small program — and hand it over to run locally:
> validated, parallelized, passed through a safety gate, all in one go, returning structured results.

Analogy: **MCP is the USB port (it defines how devices connect); IntentOS is the CPU instruction set (it defines how intent executes).**
It is not another agent framework — it's an execution engine **any agent can embed**.

**It folds three things into one layer:**

- **A stable interface** — the same primitives whether the layer below uses PowerShell, ctypes or CIM; platform quirks get absorbed inside
- **Safety, built in** — path deny-zones, confirmation for destructive operations, `dry_run` defaulting to preview-only. All **hard-coded in the interpreter**, never left to the model's good behaviour
- **One batch, one hand-off** — DAG-parallel execution, so you stop paying a model round trip per operation

**Zero dependencies**: the core uses only the Python standard library. The single external dependency, `pywin32`, is needed by just a few clipboard/COM primitives — everything else runs without it.

> ⚠️ **Platform status, stated plainly**: the kernel (IR spec / interpreter / policy gate) is platform-agnostic, but
> **the primitives implemented here are Windows-only** (processes, services, registry, scheduled tasks, …).
> The route to other platforms is the design itself — add a `primitives/` set for that platform and the kernel doesn't change a line.

---

## See it in 30 seconds

```bash
python core/interpreter.py
```

No API calls, no configuration. You'll see:

```
✅ ok=True   结果都落在寄存器里: ['sys', 'disks', 'svc']
   system.info  → Windows AMD64 · 内存 16110MB 总 / 5691MB 可用
   service.list → 运行中 3 条
   disk.list    → {'ok': True, 'count': 2, ...}

🚫 {'ok': False, 'errors': ["指令[0] 依赖 'never_defined' 未定义"]}
   ✅ 拦住：高危原语 fs.delete 无人可确认，已拒绝。
```

> Output is shown **verbatim** — primitive descriptions and messages currently ship in Chinese; there is no English locale yet.
> Everything else in this README, including the CLI, works the same either way.

Three read-only primitives ran **in parallel**, the malformed IR was rejected by static validation **before anything executed**, and the high-risk operation was **refused because nobody was there to confirm it**.
That's what this project does.

---

## Quick start

```bash
git clone <repo-url> && cd intentos
pip install pywin32          # Windows only; most primitives work without it

# 1. Core demo — no API calls (IntentOS is a tool; there is no LLM inside)
python core/interpreter.py

# 2. Command line — for scripts and shells (list / describe / call / run / blocks / journal)
python adapters/cli.py list process
python adapters/cli.py call process.find --args '{"pattern": "python.exe"}'

# 3. Wire it into your own agent (ships three dummy tools, runs as-is)
python adapters/example_agent.py

# 4. Web panel (HTTP + dashboard)
python adapters/panel.py     # then open http://127.0.0.1:8898

# 5. Run the test suite (126 cases)
python tests/smoke_test.py
```

## Core concepts

### IR — one batch, one hand-off

IR is a **controlled instruction sequence**: which operations to run, and how they depend on each other. There are exactly three opcodes — `call` / `ask` / `finish`.

```json
{
  "instructions": [
    {"op": "call", "tool": "system.info", "args": {}, "out": "sys",  "depends_on": []},
    {"op": "call", "tool": "fs.list",     "args": {"path": "./"}, "out": "dir", "depends_on": []},
    {"op": "call", "tool": "disk.list",   "args": {}, "out": "disks", "depends_on": []},
    {"op": "finish", "args": {}, "depends_on": ["sys", "dir", "disks"]}
  ]
}
```

The first three don't depend on each other, so they **run in parallel**; `finish` waits for all three.

**Producing that IR is the caller's job** — generate it with an LLM, assemble it from a template, write it by hand; IntentOS doesn't care.
To use an earlier result, write `"$register.field"` (spec in `docs/os-primitives.md`).

### Primitives — a composable set of OS capabilities

Currently **98**, spread across 19 domain files (process, file, network, registry, scheduled tasks, …).
Adding one doesn't touch the kernel:

```python
from core.factory import declare_primitive

@declare_primitive("disk.usage", "查询磁盘占用", {...schema...}, state={"used_pct": "占用%"})
def disk_usage() -> dict:
    return {"used_pct": ...}
```

(Description strings are Chinese today, as noted above.)

`load_primitives()` scans the directory and registers everything automatically — registry, state table, web panel, safety policy all follow. **Zero changes to `core/`.**

### Two gates, both inside the interpreter

| Gate | What it does |
|---|---|
| **Policy gate** | Asks about the whole batch of state-changing operations **once, up front**. One approval covers the batch; a refusal doesn't abort everything — the read-only parts still run |
| **Execution gate** | Sits on `ToolRegistry.execute`, the **single entry point** — IR, CLI, panel, scripts: every call goes through it |

Plus one default that does a lot of work: **every state-changing primitive takes a `dry_run` flag defaulting to `True`** — preview by default, and you have to say so explicitly to actually change anything.

## Usage

### Command line

```bash
python adapters/cli.py list [domain]                   # what's in the book
python adapters/cli.py describe <primitive>            # how to call one primitive
python adapters/cli.py call <primitive> --args JSON    # call one
python adapters/cli.py run <ir.json or ->              # run a whole IR (one batch)
python adapters/cli.py blocks [block]                  # tool blocks
python adapters/cli.py journal [--limit N]             # call log: what just happened
```

**Output contract (for scripts)**: stdout carries **only the result JSON** (pipe it straight into `jq`); errors and hints go to stderr.

Exit codes: `0` success / `1` execution failed / `2` usage error / **`3` blocked by the safety gate**.
`3` gets its own code on purpose — a script must be able to tell "**found nothing**" apart from "**was stopped**".

### Wiring it into your agent

Three things to do. `adapters/example_agent.py` is a complete, runnable example:

1. **Register your tools** (`source="agent"` — on a name clash yours wins, so anything your agent already does better can override the built-in)
2. **Have your agent produce an IR** and hand it to the interpreter
3. **Inject two hooks** (optional): a confirmer (asks the user about high-risk operations) and an asker (who answers `ask` instructions) — a terminal reader, an IM sender, a web click-waiter, whatever fits. **They're optional**; without them, operations that need a human fail closed

> The contract: **stateless**. It holds none of your sessions, credentials or state — whatever context it needs, you pass in as plain data.

### Tool blocks (saving tokens)

The full spec for all 98 primitives runs about **33K tokens** — a fixed cost on every turn if you inject it wholesale.
Grouped by **what they operate on** into **13 blocks**, a caller keeps only the block index resident (~1K tokens) and expands a block when it needs one — files-only work saves 75%, network troubleshooting 78%.

Inside a block, **every primitive for that object keeps its full description**: expanding `fs.list` shows `fs.entries` and `fs.tree` right beside it, so you never end up knowing one and not knowing its neighbours.
**It turns "these two are easy to confuse" from prose in a description into physical adjacency in the structure.**

### Call log

"Who touched the system?" "Did the model try to delete that folder?" "Why did this step fail?" — this is where you find out.

It hangs off **the entry point every call passes through**, so none of the 98 primitives needed changing. **Metadata only, never return values** (the first reader is the model itself, and what it wants is "what did I do", not file contents). Rotated daily under `logs/` (gitignored).

**All three outcomes are recorded**: success, failure, and **rejected by the safety gate**. That last one matters most — it's the only evidence of "the AI wanted to, and wasn't allowed to".

## Making it yours

The whole thing is built around one rule — **adding things never touches the kernel**. None of the changes below require editing `core/`:

| What you want | Where | What happens |
|---|---|---|
| **Add an OS capability** | a `@declare_primitive` declaration in `primitives/` | auto-registered into registry / state table / panel / policy. **Zero core changes** (steps in `CONTRIBUTING.md`) |
| **Drop capabilities you don't want** | move that `.py` out of `primitives/` (or point `load_primitives` at a directory holding only what you need) | those primitives simply don't exist — the model can neither see nor call them |
| **Combine primitives into one answer** | a module in `skills/` exporting `detect()` / `run()` | one call returns the conclusion; nobody re-derives the criteria each time. See `skills/README.md` |
| **Override built-ins with your own tools** | register with `source="agent"` — same name wins | capabilities your agent already does better (its own Read / Grep) replace the built-in version |
| **Show the model only part of the toolbox** | include only the blocks you need when assembling the prompt | the block index is both a partition and an exposure boundary — not listed means not exposed, which saves tokens |
| **Move to another platform** | add a `primitives/` set for it (a Linux one, say) | IR spec, interpreter and gates are platform-agnostic; the kernel stays put |
| **Change the safety policy** | the `policy` argument in a primitive's declaration | the declaration decides what needs a human nod; the decision itself always runs in `core`'s policy gate |

**Why this holds up**: `core/` knows only IR. It doesn't know who's calling, or what capabilities hang below.
Kernel and peripherals stay apart, so adding capability never touches the foundation.

> **A worked example**: `skills/proc_detective.py` ("who's running behind your back") — it crosses process, autostart and network-connection primitives into a single identity dossier and answers in one call.
> It isn't another way to list processes; it **freezes the criteria for judging where a process came from**, so the caller doesn't re-derive them every time.

## Layout

```
intentos/
├── core/                  # [kernel] platform-agnostic semantic layer
│   ├── interpreter.py     # IR spec + interpreter (static validation / DAG parallelism / $refs) + policy gate + tool registry
│   ├── factory.py         # primitive factory — declarative registration, auto registry + state, directory scan
│   ├── blocks.py          # tool blocks — 98 primitives grouped into 13 blocks, exported on demand (never auto-loaded)
│   └── journal.py         # call log — "what touched the system", hooked on execute (one hook covers everything)
├── primitives/            # [peripherals] pluggable primitives, one file per domain
│   ├── system.py          # system: platform / memory / cleanup
│   ├── process.py         # process: list / detail / kill
│   ├── service.py         # service: list / detail / start-stop
│   ├── power.py           # power: lock / shutdown-restart
│   ├── event.py           # event log: structured JSON queries
│   ├── fs.py              # files: read / write / delete / move + metadata / content search (20)
│   ├── disk.py            # disk: volumes and capacity
│   ├── net.py             # network: ports / reachability / firewall / outbound (14)
│   ├── ui.py              # interaction: clipboard / windows / screenshot / input (8)
│   ├── registry.py        # registry: read-write config + file associations
│   ├── startup.py         # autostart entries
│   ├── env.py             # environment variables: read / write
│   ├── task.py            # scheduled tasks: list and detail
│   ├── archive.py         # archives: list / extract / create
│   ├── shell.py           # shell: shortcuts · recycle bin
│   ├── acl.py             # permissions: listings
│   ├── display.py         # display: resolution / multi-monitor / brightness
│   ├── sound.py           # sound: notification beeps
│   ├── device.py          # devices: USB / printers
│   ├── _common.py         # shared helpers: cross-domain utilities and path checks
│   └── escape.py          # escape hatch: anything outside the book (separate process, confirm every time)
├── adapters/              # [integration] who uses IntentOS
│   ├── cli.py             # command line (list/describe/call/run/blocks/journal)
│   ├── example_agent.py   # integration example — register your tools, run them alongside built-ins in one IR
│   └── panel.py           # web panel — registry + state table + HTTP /status + dashboard
├── examples/              # [tooling] capability progress generator
├── docs/                  # [docs] primitive manual / capability overview / design notes / archive
└── skills/                # [capabilities] end-to-end abilities composed from primitives
    └── proc_detective.py  # example skill: process detective — "who's running behind your back"
```

## Where to read next

**Note:** `docs/` and `CONTRIBUTING.md` are Chinese-only for now — this README is the English entry point.

| Document | What it is |
|---|---|
| `docs/os-primitives.md` | ★ **primitive manual** — what's live, how to call it, safety conventions. **The only one maintained by hand** |
| `docs/os-progress.md` | **capability overview** — all 98 grouped by domain (generated; hand edits get overwritten) |
| `docs/design-notes.md` | **design notes** — why the boundary is this tight, why it isn't an MCP server, what was tried and rolled back |
| `CONTRIBUTING.md` | **contributing guide** — layout rules, adding a primitive, naming, safety tiers |
| `docs/archive/` | **archive** — documents that have done their job (worth a look when implementing new primitives) |

## What it deliberately doesn't do

In one line: **IntentOS covers local machine × single shot × stateless × no semantic understanding.**

These aren't gaps waiting to be filled — they're **deliberate non-goals**. Anything outside those four axes belongs a layer up.

| Axis | Does | Doesn't |
|---|---|---|
| **Local machine** | processes / files / ports / windows / services / registry … | cloud sync, sending email, calling third-party APIs |
| **Single shot** | one call in, one answer out — "what is it right now" | accumulation, trends, history, "where did the last sync leave off" |
| **Stateless** | holds no session, no credentials, no schedule | login state, two-way sync, long-running orchestration |
| **No semantic understanding** | read bytes, write bytes, hash bytes | reading what's inside an xlsx / PDF / image |

There's a second category: **deliberately welded-shut doors** — autostart registry keys are write-blocked, `startup` is read-only, `archive.extract` refuses symlinks. Functionally they sit one small step away, yet stay out of reach, and that's the **outcome of risk tiering**.
When you hit one, routing through `escape` or handling it a layer up is usually safer than opening the primitive up.

> The full reasoning (why the boundary is this tight, why "disable an autostart entry" was evaluated and turned down) is in `docs/design-notes.md`.

## License

[MIT](LICENSE)
