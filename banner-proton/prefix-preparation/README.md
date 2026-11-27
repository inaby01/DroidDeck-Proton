# Prefix preparation

This tool prepares game prefixes for SoftDenchi games on DroidDeck. It places a dedicated
preparation Proton slot (`SoftDenchi-Prep-Proton <upstream>-softdenchi-r<N>`), creates a new
prefix for each registered game, puts the game's declared dependencies into it (prefix DLLs,
the SoftDenchi runtime), and assigns the game to the slot in DroidDeck's settings. It runs on
the device inside DroidDeck's Ubuntu runtime. Everything is read-only until the operator
confirms what was listed. The confirmed steps write only their own new files, the game's own
entries in DroidDeck's three settings files (with backups), and, for `recovery.sh` 7 only, the
removal of that game's prefix; existing prefixes are never adopted.

Current version: 1.0.1 (`VERSION` in `preparation_common.py`). The on-screen text is Japanese.

## Contents

- [The four scripts](#the-four-scripts)
- [What a preparation does](#what-a-preparation-does)
- [Moving games to a new Proton and reverting](#moving-games-to-a-new-proton-and-reverting)
- [Preparing a game again (recovery.sh 7)](#preparing-a-game-again-recoverysh-7)
- [What the slot check accepts](#what-the-slot-check-accepts)
- [Records and private data](#records-and-private-data)
- [Diagnostic log of the SoftDenchi installer](#diagnostic-log-of-the-softdenchi-installer)
- [The bundle (bundle.json)](#the-bundle-bundlejson)
- [Building the scripts and measuring the runtime](#building-the-scripts-and-measuring-the-runtime)
- [Tests](#tests)
- [Limits](#limits)
- [Removed in 1.0.1](#removed-in-101)

## The four scripts

A bundle produces four scripts. Each embeds the same sources and the bundle, and runs on its
own (`bash prepare.sh`, no arguments). Assets (the payload archive, the SoftDenchi installer,
prefix DLLs) are read from the folder the script is in.

| Script | Use | Writes |
| --- | --- | --- |
| `prepare.sh` | Lists everything this bundle would do (placement, moves, new and resumed preparations), then one yes/no confirmation runs all of it. | yes |
| `status.sh` | The state of each game this tool initialized. | result JSON only |
| `diagnose.sh` | Measures DroidDeck's runtime (OS, the pinned scripts, hook libraries, label, umask, environment presence) and lists each item next to the bundle's `runtime_reference`, with the runtime check's own verdict. For finding what a DroidDeck update changed. | result JSON only |
| `recovery.sh` | Rare operations, see below. | per operation |

`recovery.sh` offers:

1. Prepare one game (a game the batch run does not prepare: a non-ASCII EXE path, a profile
   choice, resuming).
2. Move one game to the new Proton.
3. Revert a game to the previous slot.
4. Initialize a new prefix only (before 5; the game is not started).
5. Install SoftDenchi with its installer window (to read the licence on screen, or when the
   silent installation installed nothing).
6. Read the SoftDenchi state (read-only).
7. Prepare a game again under the same registration (see below).

Operational notes:

- Guidance names these scripts. `menu_ref` / `one_pass_ref` in `preparation_selection.py` map
  the earlier menu numbers 8, 9, 10 and 12 to `recovery.sh` 5, 6, 4 and 1.
- The slot's `user_settings.py` sets only `PROTON_SOFTDENCHI_CLEANUP=1`. Proton's debug log is
  off; add `PROTON_LOG=1` to one game's environment in DroidDeck to collect it.
- Only `cleanup` is accepted as installation mode, and only archives named
  `DroidDeck-Proton-<upstream>-softdenchi-r<N>-aarch64.tar.gz`.
- When the bundle enables it (`diagnostics.installer_log`), the installer log of a preparation
  is always collected privately (a preparation cannot be repeated after a stop) and copied to
  the shared folder only after a stop and a confirmation.
- An interrupted placement of the bundle slot (an installation record left `running` or
  `needs-inspection`) is listed by `prepare.sh` as "finish the placement record". Under the
  slot lock the tree is verified again, then each record is finished on its own: a
  `publish-intent`, `published` or `post-verified` record becomes `installed-tree-verified`
  when its staging wrapper is gone or empty; a `publish-intent` record whose tree is still in
  staging, and an earlier running record, become `failed` (staging kept). A run that finishes
  only some records shows them as partly finished and goes on. The slot then counts as placed,
  so a later Proton update can move games from it. A matching slot with no record that this
  tool placed it is not finished; the list names it under "しないこと" (not done).
- Removed in 1.0.1: the earlier numbered menus, the separate placement entry and the old
  command-line modes. See [Removed in 1.0.1](#removed-in-101).

### prepare.sh

- The list is read-only (no locks, no store creation, no Wine). It shows "to do" items (place
  the bundle slot, finish a placement record, save the slot's verification data, move or align
  games, resume, prepare new registrations) and "not done" items with their reason in words
  (the status check uses the same text).
- Registrations with a prefix but no record of this tool are grouped once; the tool never
  adopts an existing prefix. New registrations get `game_preparation.default_profile`, or the
  only profile without a pinned EXE hash; with two or more such profiles and no default they
  are listed as not done. Non-ASCII EXE paths are left to `recovery.sh` 1.
- When a SoftDenchi installation is listed, the installer name, hash, arguments and the
  licence sentence are shown; the one confirmation includes that consent and the SdProxy
  SIGTERM rule.
- Without the bundle slot, only the placement is listed. It uses an automatically chosen
  confirmation registration (registrations assigned to a preparation slot first, then by
  number); the game is only read, never started. The list is then built again and confirmed a
  second time. When no registration can confirm, the skipped ones and their reasons are shown
  with the advice to register one game first.
- Running: each step plans again under its own locks and compares what it would write with
  what was listed (the game's entries in `games.json`, `state.json` and `config.vdf`, the move
  decision, the one-pass fixed values). A game stopped before writing is skipped; a stop after
  a game started writing, or a failure not about that game (opening the private store, a lock
  held elsewhere), ends the run. Outcomes per game: done, not started, stopped before writing,
  partially applied (with the stage, and the binding backup when it exists).
- Progress (`batch-runs/`): before a step writes, the record ID it will use (`trial_id`, prefix
  DLL `record_id`, `install_id`, `binding_id`) is saved. The next `prepare.sh` reconciles an
  unfinished run from those IDs and the private records. A binding whose changed files all
  hold their new bytes, or whose own entries all assign its slot, is shown as "only the final
  check is missing".
- Do not start games from DroidDeck while `prepare.sh` runs.

### status.sh

No locks, no store creation, no Wine and no SdProxy stop. The payload is read once; a missing
payload or an unplaced slot is reported once and leaves dependencies undetermined. Per game it
shows the initialization record, the profile, the assignment from `games.json`, `config.vdf`
and `state.json` (this bundle's slot, another Proton, none, or partial with the differing
files), the dependency states and the next step. The next step comes from the same read-only
evaluation the one-pass run uses before its confirmation (`evaluate_resume`). "Ready" means
every dependency is verified and the game is bound. A running game, or a read that changed
underneath, is shown as not checkable. One game's problems do not stop the others.

## What a preparation does

The one-pass preparation of one game (`preparation_one_pass.py`) is what `prepare.sh` runs per
game and what `recovery.sh` 1 runs for one. The order is: initialize the prefix, place prefix
DLLs, release the inherited VC++ record, install SoftDenchi, stop a lingering SdProxy, bind.

### Confirmation, fixed values and resume

- Before the confirmation (nothing written yet) it stops on: a profile dependency that is not
  `ready`, a missing or different installer or DLL asset (for a new prefix every asset is
  checked; when resuming, only a DLL still to place needs its file), an unreadable binding
  record, a profile changed since initialization (other than an accepted later revision), or a
  running game or Wine. It also stops before confirming when a later step would stop.
- The confirmation shows the registration, profile, prefix, preparation slot, each DLL, the
  SoftDenchi installer with its arguments, the licence statement, the SdProxy stop rule and the
  settings files the binding changes. It is taken for a digest of fixed values (registration
  and EXE, profile and recipe digests, assets and installer mode, private paths, payload /
  customization / runtime identity and runtime writes, binding plan). Each later step plans
  again and stops, without asking again, when its fixed values differ; a stop names the changed
  items.
- Locks: the private tool/prefix lock is held from the first write to the last step;
  DroidDeck's settings lock is held during initialization and installation, and the binding
  writer takes it itself.
- A stopped run is continued by running it again. Each step decides from its latest record and
  the current state. A stop caused by an input that changed while read records
  `reason: input-changed-during-read` and `changed_fields`.
- Not done by the tool: registering the game in DroidDeck, authentication and the first launch.

### 1. Placing the preparation slot

- The payload archive is hashed in full against the bundle's `sha512`. The slot is the archive
  tree plus six generated files (`compatibilitytool.vdf`, `user_settings.py`,
  `softdenchi-install.json`, `droiddeck-proton-wrap`, `toolmanifest.vdf`,
  `toolmanifest.vdf.droiddeck-orig`); the first three are rendered by `install-softdenchi.py`.
- The tree is written into a private staging directory under `compatibilitytools.d`, verified
  in full, and published with `renameat2(RENAME_NOREPLACE)`. There is no replacing fallback; an
  existing slot that does not match is never overwritten. Only umask 0022 or 0077 is accepted.
- The writer holds the private locks and DroidDeck's settings lock. Records in `installations`
  track staging, verification, publication intent and publication. Failed staging is kept;
  after publication any failure requires inspection and never deletes the tree.
- `placement_review` in the bundle ties the archive to a reviewed CI build (artifact ZIP and
  inner SHA-512). An ordinary registered game confirms the registration source and the
  executable DroidDeck records (`confirmation_registration`); its prefix and files are only
  read.
- Slot verification data (`slot-manifests/`, written once per slot name, never replaced): the
  payload inventory, the expected generated files and the rule versions. A different or
  unreadable record makes that slot unusable as a revert target; the same contents under other
  rule versions are reported as `rules-differ`.

### 2. Initializing a new prefix

- Only for a registered game with no compatdata of either ID form (unsigned, or signed for a
  large ID). Existing prefixes stay read-only. Registrations are read from the file named by
  `BL_ADDED_GAMES`; signed 32-bit IDs are normalized to unsigned, and ambiguous registrations
  or prefix candidates stop instead of choosing.
- The fixed builtin initialization runs with the preparation slot in a guarded session.
  Records go to `game-prefixes` and bind the profile and the measured game EXE hash (an
  undeclared hash is recorded as an operator selection, not a verified edition).
- The record keeps the directory identity (device and inode) of the prefix root and of `pfx`,
  and digests of the registered EXE path and title. Later steps require the same directories,
  the recorded prefix version and the same registration.
- The record also keeps `vc_runtime_fingerprint`, the inherited VC++ runtime values right after
  initialization (used in step 4).
- A non-ASCII EXE path is warned about: such a game has been seen to exit right after start
  (cause unknown). The registration path is fixed at initialization.

### 3. Profiles and dependency handlers

A profile lists dependency IDs; each refers to a recipe in `game_preparation.recipes`.

| Handler | Can be `ready` | What it does |
| --- | --- | --- |
| `softdenchi-interactive` | yes | Installs the SoftDenchi runtime (recipe in `preparation_softdenchi_recipe.py`: runtime 5.0.9.0, revision 1). |
| `prefix-dll` | yes | Places one x86 DLL into the prefix's `syswow64`. |
| `game-folder-file` | yes | Checks, read-only, that a declared DLL exists in the game folder. |
| `mfc-local` | no | Reserved; always `blocked`. |

- A profile may have no dependencies: the prefix is only initialized and bound; nothing is
  installed or placed and the VC++ record is left alone.
- A later revision of the profile bound at initialization is accepted when it has the same
  `profile_id`, a higher revision and a pinned EXE hash equal to the one measured at
  initialization. A profile without a pinned EXE hash cannot get a later revision for an
  initialized prefix; give a changed profile a new `profile_id`.
- Dependency states: `absent`, `partial`, `incompatible`, `present-unverified`,
  `present-verified`, `uninspected`. Only `present-verified` lets binding proceed.
  `present-verified` means a match with the declaration; whether the game loads a file is only
  observable at launch.

#### prefix-dll

- The recipe has an asset declaration (manifest format) and `"destination": "syswow64"`. A
  ready recipe needs an x86 PE, reviewed provenance, `personal-use-reviewed` terms, a known size
  and SHA-256. The name is a short ASCII basename ending in `.dll`, placed in lower case; two
  DLLs of one profile may not share a name. Asset limit 64 MiB.
- Refused: a name the payload ships under `files/lib/wine/` or `files/share/default_pfx*/`, and
  a `syswow64` whose x86 layout cannot be confirmed (`syswow64/kernel32.dll` must link to the
  verified payload's `i386-windows/kernel32.dll`, or be an x86 regular file). `system32` is not
  used.
- Copy: under the private and DroidDeck locks with a clear process view, relative to one opened
  `syswow64`. The name is created with `O_EXCL|O_NOFOLLOW` (never replaced), recorded as
  `created` at once, written and read back. Nothing is removed, renamed, truncated or written
  again later. Registry, DLL overrides, regsvr32 and the game folder are not touched; Wine is not
  started.
- Records: `prefix-dlls` (phases `planned`, `created`, `present-verified`, `failed`). A partial
  file left by an interrupted write is never written again; the run stops and the operator
  removes it.

#### game-folder-file

Declares a file by name, size, SHA-256 and PE architecture, with the EXE hash and import it was
derived from; the profile must pin that EXE hash. `present-verified` means exactly one
single-link regular file of that ASCII name (case-insensitive) directly in the EXE's folder,
matching the declaration and the EXE's architecture. Nothing is copied or moved.

### 4. Releasing the inherited VC++ runtime record

DroidDeck appends Steam redistributable flags and `Software\Microsoft\VisualStudio\14.0\VC\Runtimes`
values to a tool's template prefix at its first session with that tool. A prefix created
afterwards inherits them, and the SoftDenchi installer then skips its VC++ prerequisite and
stops part way. Right before every SoftDenchi installer run the tool checks the prefix:

- If the six keys hold only the template's own values (the original part of the slot's
  `default_pfx_arm64/system.reg`, hash-checked), nothing is written: `template-original`.
- Otherwise the values are released only when SoftDenchi is not installed, no `mfc140.dll` and
  no VC++ 14.x Uninstall entry exists, the values equal the template's appended tail and the
  initialization fingerprint, and the registry has the shape Wine writes. The template's own
  values are written back and the added ones deleted with one `reg.exe` run; the registry is then
  read again. Nothing is signalled.
- Any failure stops before the installer as `stopped-before-installer` with
  `inherited_vc_record` saying why and whether running again can clear it (for example
  `template-unreadable`). Final stops (`template-mismatch`, `investigation-required`, a missing
  fingerprint, ...) are shown as stops and skipped by the batch run.
- DroidDeck may append its block to a prefix between initialization and the installer (it does
  so without a lock). Such a prefix stops and has to be prepared again; run a preparation in one
  go.

### 5. Installing SoftDenchi

- One-pass runs use the pinned silent arguments `/s /v/qn /vREBOOT=ReallySuppress`
  (`SILENT_LAUNCH`, bound to the bootstrap hash). The record states `installer.mode = silent`,
  `gui_check.status = not-applicable` and `license_consent = one-pass-confirmation`.
- Interactive fallback: only when the silent run installs nothing (`cancelled-absent`), the run
  plans the interactive installer and asks for a separate confirmation.
- `recovery.sh` 5 runs the interactive installer: a Wine `winver` window is shown first, then
  the bootstrap from a private copy with no arguments. The licence is accepted, or not, by the
  operator in the installer window. It lists the game prefixes this tool initialized.
- Installation runs only when the live state is `absent`. A failed or completed installer
  record, or an unreadable one, blocks a new attempt for review; nothing is repaired, upgraded,
  removed or retried on another prefix.
- The result comes from an offline inspection after the process view is clear: product
  registration and version, recipe files (size, SHA-256, PE machine), the UCManSvc service and
  the MSI COM class entries. Only recipe-listed keys of `system.reg` are read; `user.reg` is not
  read. Other product traces prevent `absent`. Windows exit codes cannot be observed.
- Timeouts never kill a process. While the installer runs the tool waits without asking for the
  first 10 minutes, then asks every 30 s; `q` leaves the child running and records
  `needs-user`. Records live in `dependency-installs`.

### 6. Stopping a lingering SdProxy

The SoftDenchi service can keep Wine running after the bootstrap exits. The process inventory
records PID, start time, parent, a role (`wineserver`, `wine-infrastructure`, `proton-xalia`,
`softdenchi-service`, `softdenchi-proxy`, `other`) and the image basename; no environment values
or arguments.

- SIGTERM only, and only to SdProxy processes whose parent chain reaches UCManSvc under
  `services.exe`, or (right after this run's installer) a chain whose first SdProxy was observed
  as a descendant of the installer process (origin `installer-run`). The view must be read twice
  identically, with nothing unreadable, unclassified or belonging to another prefix.
- Targets are pinned with pidfds and checked again. After each SIGTERM the tool waits for the
  target to exit and for the view to settle; the next send is allowed only while the view has
  merely shrunk. Anything new or changed aborts (`not-shrinking`, `timeout`).
- There is no SIGKILL, no `wineserver -k`, and no other process, prefix or game is signalled. If
  the view does not clear, the state stays `needs-user`. In a one-pass run the stop is confirmed
  by the one-pass confirmation (`stop.confirmation = one-pass-preapproved`).

### 7. Binding the game to the slot

The binding writer (`preparation_binding.py`) changes only this game's entries:

- `games.json`: its custom-tool choice;
- `config/config.vdf`: its compatibility-tool mapping;
- `state.json`: its applied choice and selection history (`games_applied`, its part of `auto`,
  `picked`, `native_choices`).

Other games' choices, pending requests and the default are kept. The VDF edit keeps unrelated
bytes; JSON files keep unrelated values (formatting can change). Unknown formats stop.

- Binding requires every dependency `present-verified` and the target game and Wine seen stopped
  before and after the dependency checks. These checks, the registration, the slot tree and the
  prefix are checked again right before each file is replaced.
- The writer holds the private locks and takes DroidDeck's `settings/lock` (non-blocking). It
  saves backups (`backups/binding-<id>/{games,config,state}.backup`, private, do not share), a
  supplementary record in `binding-notes/` (before/after hashes) and a record in `bindings/`.
- Files are written atomically in the order games, config, state, skipping identical files. A
  partial failure records `binding-failed` and the files already replaced; there is no rollback.
  `binding-verified` means the target settings match. `preparation_complete` is never set; a
  normal launch must still be verified.
- A normal binding can only assign the bundle slot; a `revert` binding can only assign another
  slot.

### Safety rules

- Read-only until confirmed; each write step plans again under its locks and stops on any
  difference from what was confirmed.
- Existing prefixes are never adopted, overwritten or removed (except by `recovery.sh` 7 after
  its own confirmation). Existing files are never replaced, except DroidDeck's three settings
  files by the binding (atomically, after a backup) and the `__pycache__` directories a revert
  moves into the private store.
- No SIGKILL and no `wineserver -k`; timeouts never kill.
- Records are kept, never deleted; unreadable records stop instead of being guessed.
- No authentication is performed and no game is launched.
- Tool launches set `PYTHONDONTWRITEBYTECODE=1` and an absent `PYTHONPYCACHEPREFIX`, so they
  never run the slot's bytecode caches.
- Records of newer versions carry fields that earlier tools refuse: do not run an earlier
  `prepare.sh` after a newer one.

## Moving games to a new Proton and reverting

- Moving (`recovery.sh` 2, and the batch run for slots listed in the bundle's `supersedes`):
  only games consistently assigned (all three files) to another preparation slot this tool
  placed (an `installed-tree-verified` placement record). Dependencies must be verified, the
  prefix version must equal the bundle Proton's `CURRENT_PREFIX_VERSION`, and no game or Wine
  may run. A DroidDeck screen choice of the bundle slot whose other two files still name the old
  slot is aligned without rewriting `games.json`. Games returned from this slot, or with a
  missing supplementary record, are moved only one by one.
- The x86 layout check accepts a link into the old slot only for the move judgement
  (`previous-slot-link`); writing steps require a link into the bundle slot.
- Reverting (`recovery.sh` 3) assigns a game on the bundle slot to another slot whose saved
  verification data still verifies. It does not need the bundle slot intact and does not require
  dependencies. It checks the initialization record, the EXE, the prefix, the target slot and that
  no process uses it. The verified `__pycache__` directories of the slot are moved into the
  private store (`slot-caches/<binding_id>/`, never deleted) before the settings are written.

## Preparing a game again (recovery.sh 7)

- Offered for a registration with a prefix (either ID form), tool records or a private work
  folder of its ID, when there is no binding record of that ID (it never reached "ready").
- Not offered when a record that may belong to it cannot be read; when DroidDeck's settings
  cannot be read or choose a SoftDenchi Proton for it; when the prefix holds a SoftDenchi folder
  (`SoftDenchi` under `Program Files (x86)` or `Program Files`, or `windows/ucharge`; links not
  followed) that no run of the tool's installer in this prefix explains, or that cannot be
  inspected; when both prefix forms exist; or when the prefix or work folder is not our own
  directory.
- Under the lock it checks again and stops if the prefix differs from the one confirmed or a game
  or Wine runs in it. It then renames the prefix out of DroidDeck's view, moves the tool's records
  of that ID to `retired/<redo id>/` in the private store (never deleted), renames the work folder
  to `retired-<id>`, and removes the prefix without following links.
- A hidden folder left by a `redos` record is removed the next time 7 is opened, when no game or
  Wine of that prefix runs. An interruption before the records moved leaves them alone; 7 offers
  the game again.
- The next `prepare.sh` lists the game as new. Saves in the game folder are not touched; the
  SoftDenchi authentication inside the prefix is gone.

## What the slot check accepts

The runtime-contract verifier (`verify_fex_runtime_tree`) requires the slot to match the archive
plus the generated files, with three bounded exceptions:

- FEX's one empty, owned, 0700 `files/share/fex-emu/AppConfig` directory.
- DroidDeck's appended tail of `files/share/default_pfx_arm64/system.reg` (the original bytes
  stay a prefix; at most 8 KiB of CommonRedist and VC++ `Runtimes` sections) with its
  `.droiddeck-redists` / `.droiddeck-redists-checked` markers.
- CPython `__pycache__` directories next to reviewed `.py` sources, holding only matching
  `<stem>.cpython-3NN.pyc` files with the source's mtime and size.

This weakens the check: cached bytecode is hashed but not compared with the source. The accepted
state is reported as `tool_runtime_writes`, is part of plan digests, and must be unchanged when a
step writes. Failures are located (`redist-registry-tail`, `redist-marker`, `python-cache`, ...).
To clear a `python-cache` stop, remove the reported `__pycache__` directory of the slot; the next
game launch recreates it.

## Records and private data

Private store: `~/.local/state/droiddeck-prefix-preparation/tool-store` (0700 directories, 0600
files). Per-game work folders: `~/.local/share/droiddeck-preparation-work/<id>`.

| Directory | Contents |
| --- | --- |
| `assets` | Private copies of the installer assets, with a receipt. |
| `installations` | Placement of a slot. |
| `slot-manifests` | Slot verification data. |
| `game-prefixes` | Prefix initialization (profile, EXE hash, identities, VC++ fingerprint). |
| `prefix-dlls` | Prefix DLL placement. |
| `dependency-installs` | SoftDenchi installation attempts. |
| `installer-logs` | Installer log state per attempt. |
| `bindings`, `binding-notes`, `backups` | Binding records, supplementary records, settings backups. |
| `slot-caches` | Caches moved out of a slot by a revert. |
| `batch-runs` | Progress of `prepare.sh` runs. |
| `redos`, `retired` | `recovery.sh` 7 records and the records it moved aside. |

Records of removed features (probe receipts, dedicated trials, rechecks, launches, local runs)
may still exist in a store written by an earlier version; the tool no longer reads them. Backups
and logs contain private data and device paths; do not share them.

## Diagnostic log of the SoftDenchi installer

Off unless the bundle sets `"diagnostics": {"installer_log": true}`.

- Each installer run (silent and interactive) gets `WINEDEBUG=fixme-all,warn+msi` and the
  InstallShield option `/debuglog...` into the prefix's `windows\temp`. Standard error goes to a
  private append-only file `logs/<install_id>/live.log` in the game's work folder; other
  launches keep `WINEDEBUG=-all`.
- `installer-logs/<install_id>.json` stays `open` until the installer has exited and no process
  of the prefix is visible; then the log is fixed as `final.log`. The status check lists open
  attempts.
- Results carry only a summary of allowed forms (counts per channel and function, MSI return
  values, standard action names). No paths.
- When an installation did not end `present-verified`, the screen offers to copy the log (and the
  InstallShield log) next to the shared result, after saying the copy contains device paths and
  cannot be recalled once shared.
- The log has no size cap while written, and an empty log does not prove there was no error.

## The bundle (bundle.json)

`validate_selection_config` accepts `schema_version` (1), `payload` and `runtime_reference`
(required) and `probe_material`, `placement_review`, `initialization_trial`,
`dependency_installation`, `game_preparation`, `supersedes`, `diagnostics` (optional). Script
emission additionally requires an operational bundle (`operational_layout`): `probe_material`
true, `initialization_trial` true, and `placement_review`, `game_preparation` and
`dependency_installation` present. The two flags no longer enable any menu; they are kept
because the layout check still requires them.

```json
{
  "schema_version": 1,
  "payload": {
    "archive": "DroidDeck-Proton-<upstream>-softdenchi-r<N>-aarch64.tar.gz",
    "sha512": "<128 hex>",
    "root": "DroidDeck-Proton <upstream>-softdenchi-r<N>",
    "mode": "cleanup",
    "tool_slot": "preparation"
  },
  "runtime_reference": { "...": "output of the runtime audit on the device" },
  "probe_material": true,
  "initialization_trial": true,
  "placement_review": { "...": "see below" },
  "dependency_installation": { "handler": "softdenchi-interactive", "recipe_revision": 1, "asset": { "...": "manifest entry" } },
  "game_preparation": { "profiles": [], "recipes": [], "default_profile": "<profile_id>" },
  "supersedes": ["SoftDenchi-Prep-Proton <older>"],
  "diagnostics": { "installer_log": false }
}
```

- `payload`: `archive`, `sha512`, `root` (must match the archive name), `mode` (`cleanup` only);
  optional `alternate_relative_path` (a relative path ending in the archive name) and `tool_slot`
  (must be `preparation` when `placement_review` is present).
- `runtime_reference`: the JSON of a live runtime audit (`--emit-runtime-audit`). The runtime
  check and `diagnose.sh` compare against it.
- `placement_review`: `schema_version` 1, `basis: "github-artifact-zip-and-inner-sha512"`,
  `archive_sha512` (must equal `payload.sha512`), `source_commit`, `run_id`, `artifact_id`,
  `artifact_zip_sha256`, `build_info_sha256`, optional `private_xalia_files`.
- `dependency_installation`: `handler` (`softdenchi-interactive`), `recipe_revision`, and one
  `asset` in the asset manifest format. The asset must be the recipe's exact bootstrap.
- `game_preparation`: `profiles` and `recipes` (1-64 each) and optional `default_profile`.
  - Profile: `profile_id`, `revision`, `title`, `edition`, `edition_status`
    (`unconfirmed`/`confirmed`), `dependencies` (recipe IDs, may be empty), `exe_sha256` (or
    null).
  - Recipe: `dependency_id`, `revision`, `handler`, `status` (`ready`/`blocked`), `reason`;
    `prefix-dll` adds `asset` and `destination`; `game-folder-file` adds `file` (`name`, `size`,
    `sha256`, `pe_machine`) and `required_by` (`exe_sha256`, `import`).
  - `default_profile` must name a profile without an EXE hash.
- `supersedes`: earlier preparation slot names whose games the batch run moves (at most 64; not
  the bundle's own slot).
- `diagnostics`: only `installer_log`, a strict boolean.

Asset manifest entry fields: `asset_id`, `revision`, `version`, `purpose`, `filename`, `format`,
`pe_machine`, `expected_size`, `expected_sha256`, `hash_kind`, `hash_reference`, `source_kind`,
`source_reference`, `acquired_on`, `provenance_status`, `terms_status`.

## Building the scripts and measuring the runtime

`prepare_game.py` (or the wrapper `prepare-game.sh`, which runs it with `/usr/bin/python3 -I -B`)
is a build-time tool with three modes:

```bash
# Emit one script of a bundle (prepare is the default entry)
bash prepare-game.sh --emit-selection-script --selection-config bundle.json --script-entry prepare > prepare.sh
bash prepare-game.sh --emit-selection-script --selection-config bundle.json --script-entry status > status.sh
bash prepare-game.sh --emit-selection-script --selection-config bundle.json --script-entry diagnose > diagnose.sh
bash prepare-game.sh --emit-selection-script --selection-config bundle.json --script-entry recovery > recovery.sh

# Print a self-contained read-only audit command to paste into the device terminal
bash prepare-game.sh --emit-runtime-audit

# Read-only runtime inventory of a root (sources, libraries, label, sockets)
bash prepare-game.sh --inspect-runtime --runtime-root /
```

- Emission refuses a bundle that is not operational or does not validate. The script embeds the
  `preparation_*.py` modules, `install-softdenchi.py` from `banner-proton/` and the bundle; it
  takes input through FD 3 so the Python heredoc can use stdin.
- Inputs are rejected with a fixed message, without echoing paths or input content.
- Neither runtime mode connects to sockets or prints environment values.

## Tests

Primary validation is the Linux/arm64 container (Ubuntu 26.04, Python 3.14, the same family as
DroidDeck's runtime). From the repository root:

```bash
bash banner-proton/prefix-preparation/container/run-tests.sh
```

It builds a test image from an allowlisted snapshot and runs every suite as uid:gid `0:0` and
`10000:10000`, with no network, a read-only source tree and a tmpfs for fixtures. A new test file
must be added to both `run-tests.sh` (copy list) and `run-in-container.sh` (run list). See
[container/README.md](container/README.md). Host runs on macOS are supplementary.

The tests do not run Wine or a real installer and do not establish device equivalence; GUI,
Wine, authentication and game operation are outside them.

## Limits

- `present-verified` is a match with a declaration; whether a game loads a DLL is seen only at
  launch.
- A game whose EXE path has non-ASCII characters has been seen to exit right after start.
- DroidDeck can append its VC++ block to a new prefix at any time without a lock; a prefix hit
  between initialization and the installer has to be prepared again.
- The directory identities in records would also refuse after a device-number change across
  reboots; not measured on the device.
- Whether a placed prefix DLL is kept when games move to a new Proton has not been checked on a
  device.

## Removed in 1.0.1

The last version containing these is commit `dfd3eb81` (tool 1.0.0); read them with
`git show dfd3eb81:banner-proton/prefix-preparation/<file>`.

- The earlier numbered screen (menus 1-12) and the plan-only selection screen.
- The dedicated registration probe: material creation, its recovery (`preparation_probe_recovery.py`),
  its verification and placement through it (`preparation_probe.py`), the probe initialization
  trial and its records, the post-trial audit (`preparation_trial_audit.py`), the recheck command
  and its records, and binding-only menu 11. A registration whose EXE is the probe file is now
  listed like any other registration.
- The full-readiness slot writer (`apply_installation`) and the launch records of the earlier
  ordinary launcher.
- The standalone placement entries.
- Measured dependency plans (`preparation_dependencies.py`) and the runtime preflight
  (`preparation_preflight.py`).
- The command-line modes `--inspect`, `--plan`, `--plan-dependency`, `--plan-preparation`,
  `--stage-local`, `--list-local`, `--inspect-preflight`, `--emit-preflight-script`,
  `--inspect-payload` and `--select-plan`, and the binding diagnostics.
