# SuperUser 🦾

**The file operations you already know from Yazi — now with the privileges to back them up.**

SuperUser is a lightweight, dependency-free privilege-escalation layer for
[Yazi](https://github.com/sxyazi/yazi). It sits *underneath* the normal
keybindings, so a paste into `/etc`, a delete in a system directory, or a
chmod on a service file behaves exactly like it does in your home folder —
except it *works*.

No root shell. No `sudo !!`. No workflow-breaking "permission denied" and a
climb back up the directory tree to do it by hand. Just press the key and
SuperUser decides, per target, whether it needs authority — and asks for it
only when it does.

```text
~/src          → p, d, r, a     behave normally. You'd never know we were here.
/etc/nginx     → p, d, r, a     → SuperUser steps in, authenticates, done.
```

**Nothing changes in your muscle memory. Only the failures disappear.**

---

## Why this was missing

Yazi's model is "one user, one process." That's correct and safe for 99% of
file management, but the moment you administer a system — edit a daemon's
config, clean `/var/log`, harden a deployed tree — that model turns against
you. Every privileged touch is a context switch to a terminal, a manual
`sudo`, then back to Yazi to confirm it actually happened.

SuperUser removes that gap entirely. It's the first plugin that makes
privilege escalation *invisible*: not a separate set of keybindings, not a
separate mode — the same ones you already use, made to work everywhere.

One plugin. Both privilege domains. Zero friction.

---

## How it works — the triage

Every operation passes through a **triage** before it runs. Using metadata
Yazi already has (owner, group, permission bits via `fs.cha()`) and your own
identity (`ya.uid()` / `ya.gid()`), SuperUser answers one question:

> *Can the current user do this, right now, without root?*

| Answer | Result |
|--------|--------|
| **Yes** | Yazi's own built-in runs. No prompt, no subprocess, full undo history and XDG trash. |
| **No** | SuperUser escalates through your chosen tool and runs the operation as root. |

| Op | What the triage checks |
| ---- | ------------------------ |
| `paste` / `link` / `hardlink` / `create` | write+execute on the current directory |
| `rename` (single file) | write on the file's parent |
| `rename` (multi / bulk) | — *(see [Bulk rename](#bulk-rename) below)* |
| `remove` | write+execute on **each** entry's parent, plus write inside non-empty directories |
| `chmod` | **ownership** of the target (chmod is ownership-gated, not permission-gated — a `444` file you own can be flipped to `777` without root) |

Ambiguous cases — a vanished path, a platform without Unix mode bits —
always fall back to escalation, never to a silent no-op.

---

## The operations

- **copy / move** (`p`, `P`) — with `--force` to overwrite without asking
- **rename** — inline for single files, Yazi's editor for batches
- **delete** — to the XDG trash (`d`) or permanently (`D`)
- **links** — absolute symlink, relative symlink, hardlink (`-`, `_`, `L`)
- **create** — file or directory, exactly as `touch`/`mkdir`
- **chmod** — ownership-aware, `rwx` symbolic or octal input

Every one is atomic, every one is confirmable, every one runs with the same
flags you'd type by hand. Under the hood they are a small, auditable
pure-POSIX `sh` script — nothing you don't already have installed.

---

## Safety, by design

SuperUser is deliberately *boring* about the dangerous parts:

- **Confirmation dialogs everywhere destructive.** Remove asks. Permanent
  delete asks again. Rename refuses to overwrite an existing file.
- **No cached credentials.** `sudo -k` / fresh `doas` / fresh polkit on every
  invocation. You will never fat-finger a privileged op because a password
  is still warm from five minutes ago.
- **Auditability.** The entire privileged surface is `shell.sh` — ~300 lines
  of plain POSIX you can read in a sitting.
- **Bulk rename never escalates.** See below.

### Bulk rename

Bulk renaming opens your `$EDITOR` (or an [opener](#an-honest-note-on-bulk-rename))
on a temp file of paths. Piping a multi-file editor session through `sudo`
is an attack surface (your editor, with root, on arbitrary file lists), so
**SuperUser refuses to escalate bulk rename** and tells you why:

> Bulk rename needs the external editor and cannot be escalated safely.
> Rename these files one at a time, or fix directory ownership first.

The workaround that *is* safe: `chmod`/`chown` the directory to yourself
(with escalation), bulk rename as your user, then return ownership. The
triage routes each of those steps correctly on its own.

---

## Installation

```bash
ya pkg add sail3r/superuser
```

That's the whole dependency tree. SuperUser assumes only:

- a POSIX `/bin/sh` and the core utilities already on every Linux/BSD system
  (`cp`, `mv`, `ln`, `rm`, `mkdir`, `touch`, `chmod`, `mktemp`, `sed`, `date`)
- one privilege-escalation tool: `sudo`, `sudo-rs`, `run0`, or `doas`

No Python, no node, no build step.

## Setup

You can leave every default and it works. If you want to choose your
escalator:

```lua
-- init.lua
require("superuser"):setup({
    -- options: "sudo" (default), "sudo-rs", "run0", "doas"
    tool = "doas",
    -- Emit `-v` to cp/mv/ln for verbose output.
    verbose = false,
})
```

| Tool      | Command run            |
|-----------|------------------------|
| `sudo`    | `sudo -k -- <cmd>`     |
| `sudo-rs` | `sudo-rs -k -- <cmd>`  |
| `run0`    | `run0 <cmd>` (polkit)  |
| `doas`    | `doas <cmd>`           |

## Keymaps

This is the point of SuperUser: **you don't need extra keybindings.** The
same keys you already use for user-owned files become the keys that work
everywhere. Place these in your `keymap.toml`:

```toml
prepend_keymap = [
    { on = "p",  run = "plugin superuser -- paste",                 desc = "Paste" },
    { on = "P",  run = "plugin superuser -- paste --force",         desc = "Paste, overwrite" },
    { on = "r",  run = "plugin superuser -- rename",                desc = "Rename" },
    { on = "-",  run = "plugin superuser -- link",                  desc = "Symlink (absolute)" },
    { on = "_",  run = "plugin superuser -- link --relative",       desc = "Symlink (relative)" },
    { on = "L",  run = "plugin superuser -- hardlink",              desc = "Hardlink" },
    { on = "a",  run = "plugin superuser -- create",                desc = "Create file/dir" },
    { on = "d",  run = "plugin superuser -- remove",                desc = "Trash" },
    { on = "D",  run = "plugin superuser -- remove --permanently",  desc = "Delete permanently" },
    { on = "M",  run = "plugin superuser -- chmod",                 desc = "Chmod" },
]
```

Prefer a dedicated prefix instead of replacing the defaults? Substitute an
`["s", ...]` lead — everything still works, escalated or not.

---

## Troubleshooting

### Bulk Rename

If bulk rename in a user-owned directory reports **"No text opener found"**,
the cause is almost always Yazi's opener config, not this plugin. Bulk
rename spawns an editor by matching a temp file `bulk-rename.txt` against
your `[open]` rules; if none of them resolves to a blocking text editor,
Yazi can't start one. The fix is an opener rule such as:

```toml
# yazi.toml
[open]
prepend_rules = [
    { url = "bulk-rename.txt", use = "edit" },
]   

[opener]
edit = [
    { run = '$EDITOR "$@"', desc = "$EDITOR", block = true, for = "unix" },
]
```

This is the same config Yazi documents for bulk rename generally; the
plugin only triggers it.

## Trash semantics

`remove` (via `d`) moves to the freedesktop XDG trash —
`$XDG_DATA_HOME/Trash` (default `~/.local/share/Trash`) — writing the
`files/` and `info/` layout plus a `.trashinfo` sidecar for every entry, so
"Restore" in a trash-aware tool can put things back. `remove --permanently`
(via `D`) is ` rm -rf ` — no recovery, which is why it asks twice.

## Verbose output

`verbose = true` appends `-v` to `cp`/`mv`/`ln` so the payload prints each
file it touches. `-v` is a **GNU-coreutils extension** — absent on BSD and
busybox. Leave it `false` there.

## License

MIT. See `LICENSE`.
