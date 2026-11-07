# cfr2

Cloudflare R2 from the terminal: encrypted push and pull, credentials from
keyhole or OpenBao (never in the config file), a trash instead of delete,
checksums on every object, restore drills, short-lived share links, safe
editing of encrypted files in RAM, git-status-like sync status, a cost
report, and a yazi plugin.

> Work in progress. Not released yet.

## Commands

```
cfr2 ls [-r] [-json] [PREFIX]          list one folder level (-r: everything)
cfr2 push [--enc age|gpg|none] [--to PREFIX] [--dated] FILE|DIR...
cfr2 pull [--raw] KEY|PREFIX/ [DEST]   download, decrypt, check checksums
cfr2 cat KEY                           decrypt to stdout
cfr2 edit KEY                          decrypt into RAM, $EDITOR, re-encrypt, upload
cfr2 rm [--purge] KEY|PREFIX/          move to .trash/ (R2 empties it after 30 days)
cfr2 trash [ls | restore KEY | empty]
cfr2 verify KEY|PREFIX/                compare stored bytes with the upload checksum
cfr2 drill KEY                         restore test without writing plaintext anywhere
cfr2 status [DIR]                      synced / changed / only here / only in R2
cfr2 share [--ttl 1h] KEY              presigned link for one object (max 24 h)
cfr2 usage [--short]                   storage, operations, monthly estimate
cfr2 bucket [list | create | delete | trash-rule]
cfr2 agent [start | stop | status]     keep keys in memory for a while
cfr2 doctor | init | version
```

Any KEY can be written `BUCKET:KEY`.

## Design

- **No secrets on disk.** The config only holds references:
  `keyhole:NAME` (username = access key id, password = secret),
  `bao:MOUNT/PATH` (OpenBao KV v2) or `env:PREFIX`. A literal key is refused.
- **Encryption** uses the `age` CLI by default, so plugin identities such as
  `age-plugin-fido2-hmac` work. `gpg` is a second option (`--enc gpg`).
  Plaintext only flows through pipes; `edit` uses a RAM folder.
- **Checksums**: every upload stores `sha256` (stored bytes) and
  `plain-sha256` (plaintext) as object metadata. `pull`, `verify` and `drill`
  check them.
- **Trash**: `rm` copies to `.trash/<time>/KEY` and deletes the original.
  `cfr2 bucket trash-rule` adds an R2 lifecycle rule that expires `.trash/`.
- **Share links** are refused for buckets with `share = false`.
- **Agent**: `cfr2 agent start` resolves each key once and keeps it in memory
  (unix socket in a 0700 folder, only references from the config, idle
  timeout). `CFR2_AGENT_ONLY=1` makes background callers fail instead of
  asking for a hardware-key touch.

See `config.example.toml` and `cfr2 init`.

## yazi

`plugins/cfr2.yazi`: see its README.
