# Target-only binding (0.3.0)

This stage separates tool installation from final selection and adds a target-only
DroidDeck 0.7.1 binding adapter. Prefix initialization, dependency installation,
new tool registration, template placement and device verification remain pending.

## Read-only plan

Add `--tool-directory "Example Proton"` to a selected registration's `--inspect`
or `--plan` command. The directory must already exist under the explicit Steam
root's `compatibilitytools.d`, with a single custom tool ID, Windows-to-Linux
metadata, an installed `proton` launcher and an executable `droiddeck-proton-wrap`
selected by `toolmanifest.vdf`. Symlink/hardlink inputs are rejected.

The adapter reads those files and settings without importing helpers or running
any launcher. It plans changes to only:

- `games.json`: this registration's explicit custom-tool choice;
- `config/config.vdf`: this registration's compatibility-tool name;
- `state.json`: this registration's applied choice and selection history.

Other game choices, pending clear requests, applied history and the default are
preserved. The Steam VDF edit retains all unrelated bytes, including comments and
unknown fields; an existing target block keeps its other fields. JSON files keep
unrelated values, though serialization can change formatting when a value changes.
Legacy applied history and implicit stock followers are materialized as needed
without marking other games newly pending.

The summary includes the affected file names, target/tool, digest and count of
other pending choices. Raw settings and backup content are not printed. Presence
and measured hashes of launchers do not prove payload provenance or integrity;
the full payload remains uninspected. Unknown input formats fail closed.

There is no CLI apply mode and no command-line flag for declaring dependencies,
payload or process state verified. All plans retain the execution blocker.

## Internal writer

`apply_binding` is an internal API for later connection to the preparation engine.
It is tested with synthetic readiness callbacks. A real engine must supply fresh
checks for all four prerequisites: target registration identity, dependency
postconditions, trusted payload integrity and stopped processes. A truthy value
other than the boolean `True` does not satisfy a check.

The caller must already hold the private store's global and target locks. The
adapter then takes DroidDeck's existing `settings/lock` using nonblocking flock.
This lock filename and history semantics follow the fixed source:
[steam-compatibility at DroidDeck 0.7.1](https://github.com/Droid-Deck/DroidDeck/blob/cdff94e72c45da50af43bbceff28effaf0179caf/tools/linuxfs/overlay/usr/local/bin/steam-compatibility).
The adapter does not invoke the global synchronizer or clear other pending work.

Before writing, it recomputes the plan and compares settings, launcher hashes and
paths. The existing settings are backed up only inside the private store:

```text
backups/binding-<id>/config.backup
backups/binding-<id>/games.backup
backups/binding-<id>/state.backup
bindings/binding-<id>.json
```

Backups contain private raw settings (0700 directory / 0600 files); do not share
them. A missing original has no backup file. The journal contains status and
changed-file names, never raw settings. `--list-local` lists these objects without
printing backup contents. Incompatible or corrupt binding records are identified
as invalid; old tool journals are not automatically migrated or resumed.

Writes occur in the order games → config → state, skipping byte-identical files.
Each file is written atomically after fresh prerequisite, lock, source-content,
parent and launcher checks. An external update stops further writes. A partial
failure records `binding-failed` and the files already replaced, including a
failure immediately after replacement. No complete-settings rollback is attempted.
A fresh plan can finish the target values after a partial failure while retaining
other changes; retry is not reuse of an obsolete plan.

`binding-verified` means the target settings match after the guarded writes. It
never sets `preparation_complete`; real dependency checks and normal DroidDeck
launch binding are still required. This is not a completed game preparation flow.

## Existing setup compatibility

The earlier `setup-softdenchi.py` global finalizer was removed in 1.0.0; the preparation engine uses
the target-only adapter only.
