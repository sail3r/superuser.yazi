--- Locate the POSIX payload the plugin elevates.
---
--- mainline yazi does not expose Lua's `debug` library to plugins, so the
--- previous `debug.getinfo(1, "S")` trick fails there. Resolve the script the
--- same way yazi itself does: prefer the conventional config directories.
--- yazi's `fs.unique()` helper would need the async runtime, so use plain
--- `os.getenv`/`io.open` in this hot, module-load-time path.
---
--- Priority:
---   1. $XDG_CONFIG_HOME/yazi/plugins/superuser.yazi/shell.sh
---   2. $HOME/.config/yazi/plugins/superuser.yazi/shell.sh
---   3. $XDG_CONFIG_HOME/yazi/flavors/superuser.yazi/shell.sh (ya pkg)
---   4. $HOME/.config/yazi/flavors/superuser.yazi/shell.sh
---
--- If your install lives elsewhere, set it from init.lua:
---   require("superuser"):setup { fs_script = "/abs/path/to/shell.sh" }
local function default_fs_script()
	local xdg = os.getenv("XDG_CONFIG_HOME")
	local home = os.getenv("HOME")
	local candidates = {}
	if xdg and xdg ~= "" then
		table.insert(candidates, xdg .. "/yazi/plugins/superuser.yazi/shell.sh")
		table.insert(candidates, xdg .. "/yazi/flavors/superuser.yazi/shell.sh")
	end
	if home and home ~= "" then
		table.insert(candidates, home .. "/.config/yazi/plugins/superuser.yazi/shell.sh")
		table.insert(candidates, home .. "/.config/yazi/flavors/superuser.yazi/shell.sh")
	end
	for _, p in ipairs(candidates) do
		local fh = io.open(p, "r")
		if fh ~= nil then
			fh:close()
			return p
		end
	end
	-- Fallback: first default location (also used by the error message).
	return (xdg or ((home or "") .. "/.config")) .. "/yazi/plugins/superuser.yazi/shell.sh"
end

local FS_SCRIPT = default_fs_script()

function string:ends_with_char(suffix)
	return self:sub(-#suffix) == suffix
end

function string:is_path()
	local i = self:find("/")
	return self == "." or self == ".." or i and i ~= #self
end

function string:file_name()
	local file_name = self:match(".*/(.*)")
	if file_name ~= nil then
		return file_name
	else
		return self
	end
end

function string:parent_dir()
	local dir = self:gsub("/+$", ""):match("^(.*)/[^/]+$")
	if dir ~= nil and dir ~= "" then
		return dir
	else
		return "."
	end
end

local function list_map(self, f)
	local i = nil
	return function()
		local v
		i, v = next(self, i)
		if v then
			return f(v)
		else
			return nil
		end
	end
end

local get_state = ya.sync(function(_, cmd)
	local cwd = tostring(cx.active.current.cwd)

	if cmd == "paste" or cmd == "link" or cmd == "hardlink" then
		local yanked = {}
		for _, file in pairs(cx.yanked) do
			table.insert(yanked, tostring(file.url))
		end

		if #yanked == 0 then
			return { kind = nil, value = nil }
		end

		return {
			kind = cmd,
			value = {
				cwd = cwd,
				is_cut = cx.yanked.is_cut,
				yanked = yanked,
			},
		}
	elseif cmd == "create" then
		-- `create` only needs the CWD: it prompts for a name and never reads a
		-- hovered/selected entry. An empty directory has neither, and indexing
		-- `nil.url` here is what made `superuser_create` always fail.
		return { kind = cmd, value = { cwd = cwd } }
	elseif cmd == "remove" then
		local selected = {}

		if #cx.active.selected ~= 0 then
			for _, file in pairs(cx.active.selected) do
				table.insert(selected, tostring(file.url))
			end
		else
			local hovered = cx.active.current.hovered
			if hovered then
				table.insert(selected, tostring(hovered.url))
			end
		end

		return {
			kind = cmd,
			value = {
				cwd = cwd,
				selected = selected,
			},
		}
	elseif cmd == "rename" then
		local hovered
		local nsel = #cx.active.selected
		if nsel == 1 then
			for _, file in pairs(cx.active.selected) do
				hovered = tostring(file.url)
				break
			end
		else
			local h = cx.active.current.hovered
			if h then
				hovered = tostring(h.url)
			end
		end
		return {
			kind = cmd,
			value = {
				cwd = cwd,
				hovered = hovered,
				count = math.max(nsel, 1),
			},
		}
	elseif cmd == "chmod" then
		local selected = {}

		if #cx.active.selected ~= 0 then
			for _, file in pairs(cx.active.selected) do
				table.insert(selected, tostring(file.url))
			end
		else
			local hovered = cx.active.current.hovered
			if hovered then
				table.insert(selected, tostring(hovered.url))
			end
		end

		return {
			kind = cmd,
			value = {
				cwd = cwd,
				selected = selected,
			},
		}
	end
	return { kind = nil, value = nil }
end)

--- Supported privilege-escalation tools and the argv each prepends to the
--- underlying command. superuser.yazi runs one-shot, non-interactive, root-bound
--- commands, so every tool maps to the equivalent of a bare `sudo -k --`:
---
---   sudo    : -k  ignore cached credentials, always ask interactively
---   sudo-rs : -k  same semantics as sudo (credential cache invalidation)
---   run0    : no flags; polkit decides, isolated pty, no credential caching
---   doas    : no flag needed; each invocation prompts (or uses its own
---               persist timestamp), which is the behavior we want anyway.
local ESCALATORS = {
	sudo = { argv = { "sudo", "-k", "--" } },
	["sudo-rs"] = { argv = { "sudo-rs", "-k", "--" } },
	run0 = { argv = { "run0" } },
	doas = { argv = { "doas", "-L", ";", "doas" } }, -- -L clears the persist timestamp before the real doas runs (via ya.shell, so `;` holds)
}

--- The user's chosen privilege-escalation tool is persisted in the plugin's
--- sync-context `state` (written by `setup()` at startup from init.lua).
--- Async entries run in a FRESH isolated Lua state on every invocation, so a
--- plain module-local upvalue would silently reset to the default on each
--- keypress; we read the persisted value back through a ya.sync() peek.
local DEFAULT_ESCALATOR = "sudo"

--- Write-permission bits per class, parsed from Cha:perm()'s long form
--- ("drwxr-xr-x"; a leading type char followed by three rwx triples).
--- 26.9.1 exposes perm as a METHOD returning the string, so call it via
--- pcall to survive builds where it is instead a plain field. Returns
--- { owner=bool, group=bool, other=bool } or nil when unavailable.
local function cha_write_bits(cha)
	local perm
	if type(cha) ~= "nil" then
		local ok, res = pcall(function()
			return cha:perm()
		end)
		if ok and type(res) == "string" then
			perm = res
		elseif type(cha.perm) == "string" then -- fallback: field form
			perm = cha.perm
		end
	end
	if type(perm) ~= "string" or #perm < 10 then
		return nil
	end
	-- positions: 1=type, 2-4=owner, 5-7=group, 8-10=other (w is 3/6/9)
	return {
		owner = perm:sub(3, 3) == "w",
		group = perm:sub(6, 6) == "w",
		other = perm:sub(9, 9) == "w",
	}
end

--- Whether the file's owning group grants the current user access: exact
--- match against the process gid (the primary group yazi runs under).
local function group_match(file_gid, me)
	return file_gid ~= nil and file_gid == ya.gid()
end

local peek_escalator = ya.sync(function(state)
	return state.escalator_tool
end)

local peek_verbose = ya.sync(function(state)
	return state.verbose
end)

--- Resolve the active escalation tool. Falls back to the default when the
--- store is empty or holds an unrecognised value.
--- @return string
local function current_escalator()
	local value = peek_escalator()
	if type(value) == "string" and ESCALATORS[value] ~= nil then
		return value
	end
	return DEFAULT_ESCALATOR
end

--- Build the argv the active tool prepends to the underlying command.
--- Fresh table on every call: callers extend the result.
--- @return string[]
local function superuser_cmd()
	local argv = ESCALATORS[current_escalator()].argv
	local cmd = {}
	for i = 1, #argv do
		cmd[i] = argv[i]
	end
	return cmd
end

--- Resolve the user's verbose-output preference (set via setup()).
--- @return boolean
local function is_verbose()
	local ok = peek_verbose()
	return ok == true
end

--- The tool-appropriate optional verbose flag. `-v` is GNU-coreutils only;
--- the plugin returns "" on systems where it is unsupported (BSD/busybox) so
--- it can be passed as an argv element that the Command builder skips.
--- @return string
local function verbose_flag()
	if is_verbose() then
		return "-v"
	end
	return ""
end

--- Command builder: escalate args via the chosen tool. All supported tools
--- (sudo, sudo-rs, run0, doas) take the argv verbatim; ya-quote()d operands
--- survive the single shell parse that ya.emit("shell") applies.
--- @return string[]
local function with_escalator(args)
	local cmd = superuser_cmd()
	for _, value in ipairs(args) do
		cmd[#cmd + 1] = value
	end
	return cmd
end

local function extend_list(self, list)
	for _, value in ipairs(list) do
		table.insert(self, value)
	end
end

local function extend_iter(self, iter)
	for item in iter do
		table.insert(self, item)
	end
end

local function execute(command)
	ya.emit("shell", {
		table.concat(command, " "),
		block = true,
		confirm = true,
	})
end

-- Names of the built-in commands each superuser op falls back to when the
-- current user already has the required filesystem permissions, so pressing
-- e.g. `p` pays zero escalation cost in user-writable directories.
-- `chmod` has no built-in counterpart and always escalates.
local BUILTIN_CMD = {
	paste = "paste",
	link = "link",
	hardlink = "hardlink",
	remove = "remove",
	rename = "rename",
	create = "create",
}

local function built_in(kind, value, args)
	local name = BUILTIN_CMD[kind]
	if name == nil then
		return false -- no built-in counterpart (chmod)
	end
	args = args or {}
	if kind == "paste" then
		args.force = value.force == true
	elseif kind == "link" then
		args.relative = value.relative == true
	elseif kind == "remove" then
		args.permanently = value.permanently == true
	elseif kind == "rename" then
		-- Single selection -> hovered-only inline rename; multi -> bulk editor.
		if (value.count or 1) > 1 then
			args.hovered = false
		end
	end
	ya.emit(name, args)
	return true
end

-- Probe whether the current user may write/create/delete entries inside the
-- directory `url` refers to (which requires write+execute on it). Uses the
-- Cha from `fs.cha()` — uid/gid plus the octal permission string — checked
-- against the user's own uid/gid (`ya.uid()`/`ya.gid()`), i.e. the owner
-- triage the kernel enforces on access(2).
local function dir_writable(url, me)
	local cha = url and fs.cha(url)
	if not cha then
		return false
	end
	if me == 0 then
		return true -- root bypasses permission checks
	end
	local bits = cha_write_bits(cha)
	if bits == nil then
		return false
	end
	if cha.uid and me == cha.uid then
		return bits.owner
	end
	if group_match(cha.gid, me) then
		return bits.group
	end
	return bits.other
end

-- Probe whether the current user OWNS each url. chmod(2) requires
-- ownership (or CAP_FOWNER), NOT write permission — the owner may flip a
-- 444 file to 777 without root, which `files_writable` would wrongly
-- escalate. Resolve symlinks so ownership of the target is what's checked.
local function files_owned(urls, me)
	if me == 0 then
		return true -- root owns nothing but bypasses via CAP_FOWNER
	end
	for _, path in ipairs(urls) do
		local cha = fs.cha(Url(path), true)
		if not cha then
			return false
		end
		if type(cha.uid) ~= "number" or me ~= cha.uid then
			return false
		end
	end
	return true
end

-- Probe whether the current user may write INTO each url (required by an
-- in-place write or a cross-filesystem copy+delete move which removes the
-- source after copying). Symlinked urls are resolved so the check applies
-- to the target, mirroring what the op would operate on.
local function files_writable(urls, me)
	for _, path in ipairs(urls) do
		local cha = fs.cha(Url(path), true)
		if not cha then
			return false
		end
		if me ~= 0 then
			local bits = cha_write_bits(cha)
			if bits == nil then
				return false
			end
			local ok
			if cha.uid and me == cha.uid then
				ok = bits.owner
			elseif group_match(cha.gid, me) then
				ok = bits.group
			else
				ok = bits.other
			end
			if not ok then
				return false
			end
		end
	end
	return true
end

-- Triage: decide whether the requested op can run as the current user with
-- yazi's built-in command or must go through privilege escalation.
local function needs_escalation(state)
	local me = ya.uid()
	if me == nil then
		return true -- non-Unix platform: cannot probe, stay on the safe side
	end
	local cwd = state.value and state.value.cwd
	local kind = state.kind
	if kind == "paste" or kind == "link" or kind == "hardlink" or kind == "create" then
		-- The op only ever writes into the CWD.
		return not dir_writable(Url(cwd), me)
	elseif kind == "rename" then
		-- rename(2) needs write on the hovered file's parent directory. The
		-- sync store passes paths as plain strings, so build a Url here.
		local hovered = state.value.hovered
		if not hovered then
			return false -- nothing hovered: the built-in will no-op anyway
		end
		return not dir_writable(Url(hovered:parent_dir()), me)
	elseif kind == "remove" then
		-- unlink(2) needs write+execute on the entry's OWN parent; and when the
		-- entry is a non-empty directory, recursive removal also needs write on
		-- the directory ITSELF (to remove its children) and on down. Paths
		-- arrive as plain strings from the sync store.
		for _, path in ipairs(state.value.selected) do
			local url = Url(path)
			local cha = fs.cha(url)
			-- escalate if the target is a dir the user can't write into (can't
			-- clear its contents), OR the parent isn't user-writable.
			-- is_dir is a field on some builds, a method on others — normalize.
			local is_dir = cha and (cha.is_dir == true or (type(cha.is_dir) == "function" and cha:is_dir()))
			if is_dir and not files_writable({ path }, me) then
				return true
			end
			if not dir_writable(Url(path:parent_dir()), me) then
				return true
			end
		end
		return false
	elseif kind == "chmod" then
		-- chmod(2) needs only OWNERSHIP, not write permission.
		return not files_owned(state.value.selected, me)
	end
	return true -- unknown op: never swallow it silently
end

local function superuser_paste(value)
	local args = { "sh", ya.quote(FS_SCRIPT), value.is_cut and "mv" or "cp" }
	if value.force then
		table.insert(args, "--force")
	end
	local vf = verbose_flag()
	if vf ~= "" then
		table.insert(args, vf)
	end
	table.insert(args, "--")
	extend_iter(args, list_map(value.yanked, ya.quote))

	execute(with_escalator(args))
end

local function superuser_link(value)
	local args = { "sh", ya.quote(FS_SCRIPT), "ln" }
	if value.relative then
		table.insert(args, "--relative")
	end
	table.insert(args, "--")
	extend_iter(args, list_map(value.yanked, ya.quote))

	execute(with_escalator(args))
end

local function superuser_hardlink(value)
	local args = { "sh", ya.quote(FS_SCRIPT), "hardlink" }
	local vf = verbose_flag()
	if vf ~= "" then
		table.insert(args, vf)
	end
	table.insert(args, "--")
	extend_iter(args, list_map(value.yanked, ya.quote))

	execute(with_escalator(args))
end

--- Creation is routed through the POSIX payload running as root, so the
--- guard "target must not already exist" (shell.sh op_create) is checked under
--- the same root process that performs the touch/mkdir — never by the
--- plugin against a directory that may have changed between the yazi
--- snapshot and execution.
local function superuser_create()
	local name, event = ya.input({
		title = " SuperUser Create: ",
		pos = { "hovered", y = 2, w = 40 },
	})

	-- Input and confirm
	if event == 1 and not name:is_path() then
		local args
		if name:ends_with_char("/") then
			args = { "sh", ya.quote(FS_SCRIPT), "mkdir", "--" }
		else
			args = { "sh", ya.quote(FS_SCRIPT), "create", "--" }
		end
		table.insert(args, ya.quote(name))

		execute(with_escalator(args))
	end
end

local function superuser_rename(value)
	local old_name = tostring(value.hovered:file_name())
	local old_url = tostring(value.hovered)
	local new_name, event = ya.input({
		title = " SuperUser R-E-N-A-M-E ",
		pos = { "hovered", y = 2, w = 40 },
		value = old_name,
	})

	-- Confirmed (1), non-empty, and actually different.
	if event ~= 1 or not new_name or new_name == "" or new_name == old_name then
		return
	end

	-- Refuse to clobber an existing entry; mv(1) would overwrite silently.
	local new_url = string.format("%s/%s", old_url:parent_dir(), new_name)
	if fs.cha(Url(new_url)) then
		ya.notify({
			title = " SuperUser R-E-N-A-M-E ",
			content = string.format("'%s' already exists", new_name),
			timeout = 5,
			level = "error",
		})
		return
	end

	if new_name:is_path() then
		execute(with_escalator({ "mv", "--", ya.quote(old_url), ya.quote(new_name) }))
	else
		execute(with_escalator({ "mv", "--", ya.quote(old_url), ya.quote(new_url) }))
	end
end

-- Build a human-readable list of the paths about to be removed, one per
-- line, capped so the confirmation box stays a sane size for big selections.
local function remove_body(selected)
	local lines = {}
	local max = 12
	for i, path in ipairs(selected) do
		if i > max then
			lines[#lines + 1] = string.format("... and %d more", #selected - max)
			break
		end
		lines[#lines + 1] = path
	end
	return table.concat(lines, "\n")
end

local function superuser_remove(value)
	local selected = value.selected
	local permanently = value.permanently

	local mode = permanently and " Permanently D E L E T E selected? " or " Move selected to root's T R A S H ? "
	local answer = ya.confirm({
		pos = { "center", w = 60, h = math.min(20, 6 + #selected) },
		title = mode,
		body = remove_body(selected),
	})

	if not answer then
		return
	end

	local args = { "sh", ya.quote(FS_SCRIPT), "rm" }
	if permanently then
		table.insert(args, "--permanent")
	end
	if VERBOSE_FLAG ~= "" then
		table.insert(args, VERBOSE_FLAG)
	end
	table.insert(args, "--")
	extend_iter(args, list_map(selected, ya.quote))
	execute(with_escalator(args))
end

local function superuser_chmod(value, escalate)
	local mode, event = ya.input({
		title = " SuperUser C H M O D : ",
		pos = { "hovered", y = 2, w = 40 },
	})

	if event == 1 then
		local valid = type(mode) == "string"
			and (mode:match("^[ugoa]*[+=-][rwxXst]+$") ~= nil or mode:match("^[0-7][0-7]?[0-7]?[0-7]?$") ~= nil)
		if not valid then
			ya.notify({
				title = "superuser.yazi",
				content = string.format("Invalid chmod mode %q", tostring(mode)),
				timeout = 3,
				level = "error",
			})
			return
		end
		local args = { "chmod", "--", ya.quote(mode) }
		extend_iter(args, list_map(value.selected, ya.quote))
		if escalate == false then
			-- User already writes every target: run chmod directly, no root, no
			-- shell confirm dialog. Blocking so we can surface the exit status.
			local cmd = Command("chmod"):arg("--"):arg(mode)
			for _, p in ipairs(value.selected) do
				cmd = cmd:arg(p)
			end
			local out, err = cmd:output()
			local stderr = (out and out.stderr) or (err and tostring(err)) or ""
			if err or (out and out.status and out.status.code ~= 0) then
				ya.notify({
					title = "superuser.yazi",
					content = stderr ~= "" and stderr or ("chmod failed (" .. tostring(
						err ~= nil and err or (out and out.status and out.status.code)
					) .. ")"),
					timeout = 5,
					level = "error",
				})
			end
		else
			execute(with_escalator(args))
		end
	end
end

return {
	-- Configure the privilege-escalation tool. Call from init.lua:
	--   require("superuser"):setup { tool = "doas" }
	-- Valid tools: sudo (default), sudo-rs, run0, doas.
	--
	-- Persisted into the sync-context `state` so async entries — which run in
	-- a fresh isolated Lua state on every invocation — can read it back via
	-- `current_escalator()`.
	setup = function(state, opts)
		opts = opts or {}
		local tool = opts.tool
		if tool ~= nil then
			if ESCALATORS[tool] == nil then
				ya.notify({
					title = "superuser.yazi",
					content = string.format("Unknown superuser tool %q; keeping default %q", tool, DEFAULT_ESCALATOR),
					timeout = 5,
					level = "warn",
				})
			else
				state.escalator_tool = tool
			end
		end
		if opts.verbose ~= nil then
			state.verbose = opts.verbose == true
		end
		if type(opts.fs_script) == "string" and opts.fs_script ~= "" then
			FS_SCRIPT = opts.fs_script
		end
	end,

	entry = function(_, job)
		-- https://github.com/sxyazi/yazi/issues/1553#issuecomment-2309119135
		ya.emit("escape", { visual = true })

		local state = get_state(job.args[1])

		if state.kind == "paste" then
			state.value.force = job.args.force
		elseif state.kind == "link" then
			state.value.relative = job.args.relative
		elseif state.kind == "remove" then
			state.value.permanently = job.args.permanently
		end

		local escalate = needs_escalation(state)
		if not escalate and built_in(state.kind, state.value, {}) then
			return
		end

		if state.kind == "paste" then
			superuser_paste(state.value)
		elseif state.kind == "link" then
			superuser_link(state.value)
		elseif state.kind == "hardlink" then
			superuser_hardlink(state.value)
		elseif state.kind == "create" then
			superuser_create()
		elseif state.kind == "remove" then
			superuser_remove(state.value)
		elseif state.kind == "rename" then
			-- Bulk rename in user-writable dirs goes through yazi's built-in
			-- (external editor) via built_in. When escalation is needed it is
			-- unsafe to pipe a multi-file editor session through sudo, so refuse
			-- with an explanation and let the user rename one at a time.
			if escalate and (state.value.count or 1) > 1 then
				ya.notify({
					title = "superuser rename",
					content = "Bulk rename needs the external editor and cannot be escalated safely. Rename these files one at a time, or fix directory ownership first.",
					timeout = 6,
					level = "warn",
				})
				return
			end
			superuser_rename(state.value)
		elseif state.kind == "chmod" then
			-- escalate only when some target is NOT user-writable; when the user
			-- already writes everything, plain chmod as the current user suffices.
			superuser_chmod(state.value, escalate)
		end
	end,
}
