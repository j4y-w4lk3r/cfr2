# cfr2.yazi

Yazi plugin (yazi 26+) on top of the `cfr2` CLI.

```sh
ln -sfn /path/to/cfr2/plugins/cfr2.yazi ~/.config/yazi/plugins/cfr2.yazi
```

`init.lua`:

```lua
require("cfr2"):setup({
    markers = true,  -- sync markers in the file list (+ only here, M changed, R only in R2)
    usage   = true,  -- R2 size and monthly estimate in the status bar
})
```

`keymap.toml` (`[mgr] prepend_keymap`):

```toml
{ on = [ "b", "b" ], run = "plugin cfr2 browse",     desc = "R2: browse a bucket" },
{ on = [ "b", "p" ], run = "plugin cfr2 push",       desc = "R2: encrypt + push the selection" },
{ on = [ "b", "d" ], run = "plugin cfr2 push-dated", desc = "R2: push into a YYYY-MM-DD/ folder" },
{ on = [ "b", "r" ], run = "plugin cfr2 refresh",    desc = "R2: refresh the sync markers" },
```

The browser is an fzf picker: `enter` pull here, `ctrl-s` share link,
`ctrl-e` edit, `ctrl-d` restore drill, `ctrl-v` verify, `ctrl-x` trash,
`ctrl-b` other bucket.

Markers and the status-bar cost only run while `cfr2 agent` is running, so
yazi never asks for a hardware-key touch by itself.
