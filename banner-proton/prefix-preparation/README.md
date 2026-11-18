# Prefix preparation: offline planning and local staging (0.14.2)

`prepare-game.sh --inspect` (the default) and `--plan` inspect explicit local
inputs without any writes. `--stage-local` separately opts into caching declared
assets and journaling progress inside one explicit private management root;
`--list-local` reads its inventory. See [local staging](LOCAL-STAGING.md) for its
asset schema, write boundaries and restart procedure.
Optional `--tool-directory` adds a [target-only binding plan](BINDING.md); its guarded
internal writer is not exposed through the CLI.

`--inspect-payload` is a separate read-only mode accepting `--payload-archive`,
`--payload-sha512` and `--payload-root`. It hashes all regular archive members
without extracting them. Optional `--payload-directory` compares an unmodified
installed tree, including extra files, modes and link topology. It cannot be
combined with preparation modes. A matching operator-declared checksum establishes
identity; the report retains provenance/runtime blockers and never enables execution.

`--inspect-runtime --runtime-root /` inventories pinned runtime source files,
selected library hashes/ELF headers, label hash, environment presence, display
socket metadata and the auditor's proc/umask basis. It does not connect to sockets
or print environment values. `--emit-runtime-audit` emits a self-contained command
that can be pasted into the target terminal without installing files. Neither mode
enables prefix preparation or claims runtime compatibility. Proc failures include
stage/error diagnostics and separate numeric-PID/`proc/self` FD probes, without
printing PID values or status contents. Self-status fields use the successful
`proc/self` directory-FD reader while retaining shared-reader diagnostics. This
does not establish namespace visibility or relax launch checks.

`--plan-preparation` composes the selected registration/EXE and optional profile/
asset inspection with archive identity, pinned runtime, expected installation/
adoption metadata, installation or strict reuse, and a target-only binding plan
for an already installed matching tree. It requires the ordinary target paths,
`--payload-archive`, `--payload-sha512`, `--payload-root`, `--installation-mode`,
`--runtime-root`, and `--runtime-audit` (the prior live arm64 audit JSON). The
runtime root is re-inspected, and its private live label and supported umask are
used to generate expectations. An offline root snapshot remains planning-only;
the presence of an audit report never authorizes execution.

The composed report separates actual `writes: []` from `planned_writes`, lists
the new installation/staging paths, preserves any existing compatdata (including
partial or signed-ID directories), and estimates tool installation space from
filesystem allocation size plus a 64-MiB reserve. Prefix/dependency growth and write
permissions remain unverified. Existing installations must match the entire
archive plus the six generated metadata files, including modes and link topology.
Only generator-backed metadata modes for creation umask 0022 or 0077 are accepted;
unknown or mixed variants are rejected without repair. Archive directory modes
remain exact: the legacy installer's `data_filter` extraction under umask 0077
creates directories with mode 0700 rather than archive mode 0755, so such a tree
is refused by strict reuse. No automatic chmod or reinstall is performed.

This mode returns 2 (blocked plan). It exposes neither an installation writer nor
a prefix executor. It does not call the legacy setup's global synchronization.
The plan is an observation, not a durable authorization; future writers must
recompute/recheck it under locks and satisfy independent readiness conditions.

`--inspect-preflight` reports the live runtime and explicit/default Steam/settings
paths and their existing ancestors/capacity. It does not read prefix or settings
contents and is read-only unless `--probe-temporary` is explicitly supplied.
`--emit-preflight-script` emits an inert standalone Bash/Python script for the same
preflight, so the device needs only one script and one short command.

The opt-in probes create a new mode-0700 directory on the existing tool-parent
filesystem (or Steam root if the tool parent is absent). They test the same Linux
no-replacement publication primitive as the installation writer, including an
existing empty-directory collision. A fixed native Python child with a fictitious
prefix path tests before/during/after proc observations and direct child stat/
environ access. It creates no compatdata or pfx. Only the two prefix-related env
fields are interpreted; PID, raw environments and unrelated values are not output.
The child normally exits when its input pipe is released; its own alarm provides a
bounded fallback. No existing process is signaled.

For a local DISPLAY only, another fixed native Python child uses the system Xlib
[XOpenDisplay/XCloseDisplay API](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man3/XCloseDisplay.3.html)
to open/close the display without creating a window. It retains only required GUI
authentication environment keys, strips loader inputs, never records cookie or env
values, and has its own three-second alarm. This tests native X11 connection, not
Wine GUI, rendering, audio or normal game launch equivalence. Missing Xlib, failed
connection and deadline failure remain explicit results.

Only known unchanged empty probe directories are removed. Unexpected objects or
changed identities are retained with an inspection status and private path. Actual
temporary creation is included in `writes` even when cleaned up. Runtime/proc
scope/registration freshness and prefix/dependency capacity remain separate
blockers; even all successful probes do not grant installation/launch readiness.
Exit 2 denotes a preflight report with preparation still blocked.

A short, plan-only user launcher is available through `--emit-selection-script`.
It can embed a validated local `--selection-config` containing one declared archive
identity/layout/mode and an earlier live runtime audit reference. Local data is
not included in the public sources. Without embedded data it reads
`prepare-plan.json` alongside the launcher. Development mode `--select-plan`
runs the same selection/report flow directly.

The generated launcher is named `prepare.sh`: run `bash prepare.sh`, select a
number, and read the displayed plan. No flags, manually typed ID or output
redirection are required. It reads the file referenced by the current
`BL_ADDED_GAMES` environment variable (not JSON text in the variable), projects
known registration fields, and rechecks the source hash and selected EXE before
publishing the plan. This pins the observed runtime file; it does not prove a
fresh Android export or the normal launch route. IDs remain distinct from EXE
basenames and titles. Terminal control characters are escaped.

The selected target is joined to the existing installation/runtime planner,
including full archive and optional installed-tree verification, expected
customizations and target-only binding planning. Existing compatdata, including
empty or signed-ID entries, is preserved. A new registration/test context remains
unconfirmed until explicitly established. Planned private HOME/work paths are
separate from game/tool/Steam/settings data and are not created. Prefix template
allocation is estimated from the shipped `files/share/default_pfx_arm64` subtree;
initialization/dependency growth and complete capacity are still unmeasured. This
is distinct from a future dependency-prepared prefix template.

A new `plan-<random>.json` is normally saved alongside the launcher with mode
0600, exclusive creation, bounded size and no overwrite. When shared storage's
owner/mode metadata prevents private direct saving, an owned Linux HOME fallback
under `.local/state/droiddeck-prefix-preparation/reports` retains the authoritative
private result. New fallback directories use mode 0700; existing ancestors are
checked, never chmod/chown'ed. The result is then exported, with exclusive creation,
to the explicitly selected launcher folder. Only this report-data export accepts
shared filesystem ownership/mode emulation; its privacy depends on that filesystem.
Asset, cache, payload, private record and execution checks are unchanged.
A launcher inside Steam/settings/selected game data cannot save or export there;
a private fallback outside those roots may still retain the diagnostic. Unexpected
write failures can leave a partial new report; there is no automatic deletion.
Cancellation saves nothing. Missing/ambiguous archives retain target evidence and
report the needed filename. Other rejection reports contain only a fixed stage,
exception class/errno and a closed reason code, not raw exception or environment
values. Raw registration JSON and unrelated fields are not saved. The selected
EXE/path/title and planned paths in the report are private user data.

The standalone script embeds trusted distribution modules and the trusted
installer renderer, never the inspected helper or archive Python. Embedded source
literals are ASCII escaped to avoid source-decoding differences across shells/
Python versions. FD 3 preserves menu input while stdin carries the Python heredoc.
The script works from another CWD without importing its modules or writing
bytecode. It rejects command-line arguments. Exit 2 means a saved blocked plan;
0 means cancellation; 1 means the report could not be saved or invocation failed.
A rejection's fixed check stage/reason/class/errno is also printed before saving,
so a storage failure cannot hide the initial rejection. Selected EXE path/FD type,
link count and owner-comparison metadata are projected without reading contents
when diagnosing an input refusal. This does not relax the strict reader.
The automatic save is explicit in this user launcher; existing developer
inspection modes keep their read-only/default no-save behavior.

Selection bundle payloads may choose the fixed `tool_slot: "preparation"` instead
of the backward-compatible default `"legacy"`. It uses a distinct
`SoftDenchi-Prep-Proton <version>` directory and `SoftDenchi-Prep-Proton-<version>`
tool ID; arbitrary slot/directory names are rejected. The source archive/version,
Wine binaries and wrapper code do not change. Only generated catalog/receipt
identity metadata differs, within the same six permitted overlays.

A preparation-slot plan observes an existing legacy tree without modifying it and
does not require that unused legacy tree to match. The actual preparation slot
must still be absent or match the complete expected tree; mismatch never falls
back to the legacy tool or permits overwrite. Native synthetic installation tests
publish the preparation slot while preserving a deliberately changed legacy tree.
The live installation and game binding remain blocked pending real prerequisites.

Tree mismatch diagnostics identify the first discrepancy per creation-mask
variant: root modes, known relative member path and differing field names, missing/
unexpected object or hardlink topology. Raw file bytes, settings, link target text,
unknown extra filenames and exception text are not collected. It is a bounded
first-mismatch observation, not a complete diff or a corruption diagnosis. Existing
strict tree validation is retained. Legacy-mode rejection reports retain these
same structured diagnostics when available.

No CLI mode launches Wine, executes DroidDeck helpers or `user_settings.py`, installs
dependencies, downloads, extracts archives to disk, registers Proton, synchronizes settings,
or creates/modifies a game prefix. An internal initialization/probe launcher exists,
but is not connected to the CLI or executable recipes. It requires a complete pinned payload inventory, pinned registration/EXE and
scoped proc observations, plus caller checks for provenance and runtime/stop scope.
Local tests use a harmless substitute, not Wine. Launch records now use schema 2;
schema-1 launch records are incompatible and are not migrated.
An internal minimum-runtime plan pins source/library/label identities and a supported
umask, constructs only known loader-hook paths, and keeps environment values private.
A snapshot plan cannot authorize a live launch; provenance, process scope and actual
GUI/Wine compatibility still need caller checks.
An internal Linux installation writer now materializes a pinned archive into a
private staging directory using directory FDs, with bounded streaming and deferred
links. It applies the generated six metadata files, explicitly preserves archive
permissions under umask 0022/0077, verifies the whole completed tree, and publishes
with Linux `renameat2(RENAME_NOREPLACE)`. There is no replacing fallback if libc,
the kernel or the filesystem lacks support. See the
[Linux rename documentation](https://man7.org/linux/man-pages/man2/renameat2.2.html).
No Wine, wrapper, helper or archived Python is executed.

The writer requires the private global/target locks, DroidDeck's settings lock,
a fresh matching plan, scoped process observations and trusted caller readiness
for provenance, target freshness, runtime and complete stopped scope. A snapshot
may receive tool writes only inside that same snapshot; it cannot authorize a
live installation or launch. The live path requires the real runtime/proc roots.
New installation parents must be owned and not writable by others; unsafe archive
permissions are refused. This writer remains unavailable through the CLI.

Private `installations` records track staging, verification, publication intent and
observed publication. Failed staging is retained. After publication, any failure
requires inspection and never deletes the installed tree. If journal persistence
itself fails, the last durable phase remains; `published: false` in a publication-
intent record is not proof the destination was never created. Inventory always
requires reinspection, including after a successful identity check. No automatic
recovery, staging garbage collection or interrupted-install resume is implemented.
Only our own empty staging wrapper is removed on success. Existing prefix, game,
selection and state contents are not written by this operation.

No inspection or plan result file is saved automatically.

Use the complete directory from a trusted local installation. The entry point uses
`/usr/bin/python3 -I -B` (Python 3.9 or later), ignoring `PYTHONPATH` and avoiding
bytecode writes. It does not search the current directory or PATH for Python.

Example with synthetic paths and an explicitly chosen ID:

```bash
bash prepare-game.sh --inspect \
  --registrations /test/added-games.json \
  --steam-root /test/Steam --settings-root /test/droiddeck-compat

bash prepare-game.sh --plan \
  --registrations /test/added-games.json \
  --steam-root /test/Steam --settings-root /test/droiddeck-compat \
  --app-id 42 --exe-root /test/games \
  --profile /test/profile.json --recipes /test/recipes.json \
  --droiddeck-version 0.7.1 --proton-version example-proton-r1
```

The first command lists registrations. Select by ID with `--app-id`; selection by
name or basename is deliberately unsupported. `--exe-root` must explicitly bound
the selected executable. All explicit input paths must be absolute, without `..`,
symlink parents or `.env` files. Input files must be single-link regular files. Prefix
contents are not recursively scanned. Only the offline prefix version is read;
registry, authentication and save contents are not collected.

The registration input is the **added-games JSON list** consumed by DroidDeck
0.7.1's `droiddeck-proton-run` via `BL_ADDED_GAMES`. This stage does not discover the
Android-owned file, read Steam binary `shortcuts.vdf`, or verify the installed
DroidDeck version. Supply an existing local list explicitly; do not interpret this
as a request to change game registration. Only `appid`, `exe`, and optional
`name`/`title` are projected into the report; other registration fields are ignored.

```json
[{"appid": 42, "exe": "/test/games/Example/Game.exe", "name": "Example"}]
```

Signed 32-bit IDs are normalized to unsigned. Duplicate normalized IDs and
multiple signed/unsigned compatdata candidates are rejected. The EXE's current
SHA-256, size and PE architecture are measured without execution. A measured hash
is not provenance or a known reference hash. EXE input has a fixed 2 GiB ceiling.

Optional declarative profile (all fields required, unknown fields rejected):

```json
{
  "schema_version": 1,
  "profile_id": "example",
  "revision": 1,
  "title": "Example",
  "edition": "Unconfirmed edition",
  "edition_status": "unconfirmed",
  "droiddeck_versions": ["0.7.1"],
  "proton_versions": ["example-proton-r1"],
  "dependencies": ["example-runtime"],
  "evidence": ["Local investigation pending"],
  "exe_sha256": null
}
```

Recipe document (declarative blockers only, **no installer commands or paths**):

```json
{
  "schema_version": 1,
  "dependencies": [{
    "dependency_id": "example-runtime",
    "revision": 1,
    "handler": "mfc-local",
    "requires": [],
    "status": "blocked",
    "reason": "Asset provenance and postconditions not established"
  }]
}
```

Reserved handlers are `mfc-local` and `softdenchi-interactive`; neither is
executable in this stage. Recipes cannot declare success or arbitrary commands.
JSON inputs are limited to 1 MiB, nesting depth 16, strings of 4 KiB, 128 dependency
nodes, and dependency graph depth 16. Rendered reports are limited to 1 MiB.
Duplicate keys, unknown schema/fields, missing references, cycles and invalid scalar types are rejected.

The report includes an input digest and separate profile/recipe revisions. Local
paths and registration IDs appear in terminal output, so treat it as private.
Raw settings, environment values and unrelated configuration fields are omitted;
terminal controls are escaped. Steam's game/default mapping and the UI's choice
are reported separately. A choice alone does not prove a matching wrapper or
payload. The parser accepts bounded quoted text VDF with braces and line comments;
unsupported syntax fails closed instead of executing the installed helper.

Version arguments are operator declarations. A matching declared version or EXE
reference hash does not promote a combination to `verified`. Process state, free
space, dependency postconditions, fonts, payload integrity, sync impact and real
launch binding remain uninspected. Assets are uninspected unless a manifest is
supplied. Existing prefixes are read-only.
Every plan includes `execution-not-implemented`; inspection/plan `writes` is always
empty. Optional `--assets` and `--asset-root` inspect a local asset manifest and
include its raw digest plus measured identities in the plan digest. Asset evidence
remains operator-declared, and assets are not yet bound to executable recipes.

Exit codes: inspection `0` means a report was produced, input rejection `1`,
blocked plan or local staging paused before preparation `2`. A successful
inspection exit is not preparation completion.

Primary local validation is the [Ubuntu 26.04/arm64 container](container/README.md),
which runs these tests plus installer/setup/observer regressions as root and nonroot.
From the repository root:

```bash
bash banner-proton/prefix-preparation/container/run-tests.sh
```

Supplementary host tests (synthetic files only, from this directory):

```bash
/usr/bin/python3 -I -B test_prepare_game.py
/usr/bin/python3 -I -B test_preparation_store.py
```

The source contract was checked against DroidDeck commit
`cdff94e72c45da50af43bbceff28effaf0179caf`:
[registration and prefix resolution](https://github.com/Droid-Deck/DroidDeck/blob/cdff94e72c45da50af43bbceff28effaf0179caf/tools/linuxfs/overlay/usr/local/bin/droiddeck-proton-run).
The stricter ambiguity checks intentionally stop instead of choosing among
multiple prefix candidates. Asset caching, journal persistence and tool/prefix
preparation locks are available for local staging. A target-only binding planner/writer with the DroidDeck setting
lock is implemented and locally tested; the writer still requires connection to
real readiness checks. Executable recipes, installation CLI/readiness integration, final engine
integration and template cloning remain pending. Device
validation has not been performed for this tool.


## Dedicated registration material

An emitted `prepare.sh` with the explicit boolean bundle option
`"probe_material": true` adds a numbered common menu. Option 1 retains the
read-only target plan. Option 2 previews a **new** randomly named folder beside
`prepare.sh`, then requires a separate `1` confirmation before writing anything.
Canceling the preview writes nothing. There are no additional user flags.

Creation validates the entire pinned archive, captures only the regular x86
`files/lib/wine/i386-windows/cmd.exe` member (at most 2 MiB) in memory, and copies
it as `prefix-probe.exe`, with `probe.json`. It never executes this EXE. A private
receipt and global/target locks live under
`HOME/.local/state/droiddeck-prefix-preparation/probe-store`; a new report is
saved/exported with the existing report rules. Only these new material and private
record/report paths are written. No existing destination is reused, replaced or
repaired. Failures preserve partial material and a creating/failed receipt.

Place the launcher in an Android-accessible shared folder. In the Android EXE
picker, open that same folder, the new `DroidDeck Prefix Test-…` subfolder,
and `prefix-probe.exe` without launching it. The creation JSON includes the full
`exe` path and a `selection_hint.relative_exe` relative to the launcher folder.
Previously created private probes remain untouched; they are not moved or reused.
Then choose the new registration in the same common entry. This
Android UI path has not yet been verified on a device. The plan requires the
private ready receipt, exact marker and executable identity, the same directory
and EXE inode (allowing real bind aliases), one unambiguous new registration ID
relative to the pre-copy baseline, and absent compatdata including signed and
noncanonical numeric aliases. A missing unrelated old EXE does not become a match.
This confirms only the observed registration, not Android export freshness,
a game profile, runtime provenance, full stopped scope or permission to execute.
The registration probe remains distinct from any real game profile.

An executable name or shared marker alone never establishes a trusted probe.
Existing game files, saves, authenticated prefixes, Android registrations,
Proton installations and compatibility settings are not copied or modified.
Template creation, prefix initialization and dependency installation are still
unavailable through this user entry.


Probe verification failures report a fixed `check` and
`probe_registration_diagnostic.checks` containing only passed/failed step names.
Marker reads, private receipt/schema/readiness, Steam/source context, path inode
identity, executable bytes, baseline ID, duplicate registration, prefix absence
and final reread are distinguished. Raw receipts, marker data, unrelated game
paths, registry and environment values are never included. A diagnostic failure
does not repair, recreate, move or execute the probe. Existing 0.14.x receipts
remain readable; users can select the same registration again without creating
new material.
