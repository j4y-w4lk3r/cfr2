--- @since 26.1.0
-- cfr2.yazi: Cloudflare R2 inside yazi, through the cfr2 CLI.
--   plugin cfr2 browse       fzf picker over a bucket (pull, share, edit, drill, verify, trash)
--   plugin cfr2 push         encrypt + upload the selected (or hovered) files
--   plugin cfr2 push-dated   same, into a YYYY-MM-DD/ folder
--   plugin cfr2 refresh      re-read the sync markers for the current folder
-- setup() adds the sync markers to the file list and the cost to the status bar.

local M = {}

local MARK = {
	synced = { " ", "green" },
	changed = { "M", "yellow" },
	["local"] = { "+", "red" },
	remote = { "R", "blue" },
	unknown = { "?", "gray" },
}

local get_opts = ya.sync(function(st)
	return { bin = st.bin or "cfr2", browse = st.browse, bucket = st.bucket }
end)

local current_dir = ya.sync(function()
	return tostring(cx.active.current.cwd)
end)

local selected_paths = ya.sync(function()
	local out = {}
	for _, u in pairs(cx.active.selected) do
		out[#out + 1] = tostring(u)
	end
	if #out == 0 and cx.active.current.hovered then
		out[1] = tostring(cx.active.current.hovered.url)
	end
	return out
end)

local set_status = ya.sync(function(st, dir, map)
	st.dir, st.marks = dir, map
	ui.render()
end)

local set_usage = ya.sync(function(st, line)
	st.usage = line
	ui.render()
end)

local function notify(msg, level)
	ya.notify({ title = "cfr2", content = msg, timeout = 6, level = level or "info" })
end

local function run_in_terminal(argv)
	local permit = ui.hide()
	local child, err = Command(argv[1])
		:arg({ table.unpack(argv, 2) })
		:stdin(Command.INHERIT)
		:stdout(Command.INHERIT)
		:stderr(Command.INHERIT)
		:spawn()
	if child then
		child:wait()
	else
		notify("cannot run " .. argv[1] .. ": " .. tostring(err), "error")
	end
	permit:drop()
end

local function refresh(opts)
	local dir = current_dir()
	local out = Command(opts.bin):arg({ "status", "--json", dir }):env("CFR2_AGENT_ONLY", "1"):stdout(Command.PIPED):stderr(Command.PIPED):output()
	if not out or not out.status.success then
		set_status(dir, {})
		return
	end
	local ok, reports = pcall(ya.json_decode, out.stdout)
	if not ok or type(reports) ~= "table" or not reports[1] then
		set_status(dir, {})
		return
	end
	-- report paths are relative to the sync folder; key them by absolute path
	local root = reports[1]["local"]:gsub("^~", os.getenv("HOME") or "~")
	local map = {}
	for _, f in ipairs(reports[1].files or {}) do
		map[root .. "/" .. f.path] = f.state
		-- mark folders that contain something not backed up
		if f.state ~= "synced" then
			local d = f.path:match("^(.*)/[^/]+$")
			while d do
				map[root .. "/" .. d] = map[root .. "/" .. d] or "changed"
				d = d:match("^(.*)/[^/]+$")
			end
		end
	end
	set_status(dir, map)
end

function M:setup(opts)
	opts = opts or {}
	self.bin = opts.bin or "cfr2"
	self.browse = opts.browse_script
	self.bucket = opts.bucket
	self.marks, self.usage = {}, nil

	if opts.markers ~= false then
		Linemode:children_add(function(line)
			local st = self.marks and self.marks[tostring(line._file.url)]
			if not st then
				return ""
			end
			local m = MARK[st] or MARK.unknown
			return ui.Line({ ui.Span(" " .. m[1]):fg(m[2]) })
		end, 600)
		ps.sub("cd", function()
			ya.emit("plugin", { "cfr2", "refresh" })
		end)
	end

	if opts.usage ~= false then
		Status:children_add(function()
			if not self.usage or self.usage == "" then
				return ""
			end
			return ui.Line({ ui.Span(" " .. self.usage .. " "):fg("cyan") })
		end, 500, Status.RIGHT)
		ya.emit("plugin", { "cfr2", "usage" })
	end
end

function M:entry(job)
	local action = job.args[1] or "browse"
	local opts = get_opts()
	if action == "browse" then
		local script = opts.browse
			or (os.getenv("HOME") .. "/.config/yazi/plugins/cfr2.yazi/cfr2-browse.sh")
		run_in_terminal({ "env", "CFR2_BIN=" .. opts.bin, "bash", script, job.args[2] or opts.bucket or "", current_dir() })
		refresh(opts)
	elseif action == "push" or action == "push-dated" then
		local files = selected_paths()
		if #files == 0 then
			return notify("nothing selected", "warn")
		end
		local argv = { opts.bin, "push" }
		if action == "push-dated" then
			argv[#argv + 1] = "--dated"
		end
		for _, f in ipairs(files) do
			argv[#argv + 1] = f
		end
		run_in_terminal({ "sh", "-c", '"$@"; printf "\\n[press enter]"; read _', "cfr2-push", table.unpack(argv) })
		refresh(opts)
	elseif action == "refresh" then
		refresh(opts)
	elseif action == "usage" then
		local out = Command(opts.bin):arg({ "usage", "--cached", "--short" }):env("CFR2_AGENT_ONLY", "1"):stdout(Command.PIPED):stderr(Command.PIPED):output()
		if out and out.status.success then
			set_usage((out.stdout:gsub("%s+$", "")))
		end
	else
		notify("unknown action " .. action, "error")
	end
end

return M
