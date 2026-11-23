# Prefix preparation: offline planning, dependency planning, dedicated trial and managed dependency installation (0.23.0)

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

Ordinary inspection/planning never launches Wine, executes DroidDeck helpers or
`user_settings.py`, installs dependencies or synchronizes settings. Separately confirmed
material/placement operations and the dedicated initialization trial below are explicit
write operations. The normal readiness-gated initialization/probe launcher remains
internal and is not connected to executable recipes. It requires a complete pinned payload inventory, pinned registration/EXE and
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


A non-ready private receipt remains rejected. Before stopping, the plan additionally
records `incomplete_probe_material` with the whitelisted receipt state and
independent read-only observations of both created and registered paths, byte and
marker agreement, directory path/FD guards, existing private lock metadata and
receipt stability. It does not acquire/create locks, fsync directories, finalize
receipts or repair files. These are current observations; legacy creation reports
did not record the original failing condition and cannot replay history.
Raw private receipts, paths, marker values and exception messages are excluded.


## Explicit recovery of a failed registration-material receipt

The common launcher menu adds option 3 for existing probe registrations. This is
separate from the read-only option 1 and the new-material option 2. It previews
an exact private history path and receipt update, then requires a separate `1`.
Canceling writes nothing. No new EXE, marker, Android registration, compatdata or
Proton installation is created, modified or executed.

Recovery repeats the whole pinned archive checksum/inventory and bounded x86
member inspection, requires both material and registered EXE/marker to agree,
and checks the same registration, baseline new ID, uniqueness, absent prefix
including signed/numeric aliases, source stability and inode/metadata pins.
It does not authorize a write based on a diagnostic JSON or receipt status.
All checks are repeated under the existing private global/target locks. Receipt,
registration, material content and inode pins are checked again immediately before
the atomic receipt update; the archive is not streamed a third time in that
callback. Any mismatch stops the operation.

The original receipt is retained without overwrite under `probe-history`, named
by its original SHA-256. An identical existing backup may be reused after an
interruption; conflicting history is refused. The updated ready receipt keeps
its original creation version and adds a strict `revalidation` evidence object
with the new tool version, old state/hash/history reference, archive/inventory,
registration identity/source hash and context digest. Normal verification now
checks this immutable history and the revalidated registration ID. A previously
ready receipt is inspected without rewriting it or creating new history.

The historical reason for an old creation failure remains unknown. This is a new
revalidation, not a claim that the original run succeeded. If publication is
interrupted, private state may already have changed; preserve it and use the same
menu again. The report explicitly records the uncertain write outcome. It never
rolls back blindly or marks the receipt failed after a possibly successful update.
After recovery, the same target's normal blocked preparation plan is generated
and saved in the same operation. Prefix initialization, dependency installation,
template creation and game launch remain unavailable through this entry.


New material-creation failures also retain a strict `creation_failure` stage,
error-kind enum and bounded errno in the private failed receipt where possible.
The visible creation report uses the same fixed stage. No exception message or
input data is stored. This evidence is preserved through subsequent revalidation;
legacy failures that lack it remain explicitly unknown.


## Static placement of the reviewed preparation tool (0.16.0)

A trusted emitted bundle may include `placement_review`, recording the reviewed
GitHub build commit/run/artifact ZIP digest, build-info digest and inner archive
SHA-512. This review is pinned distribution data established before emission;
format validation alone is not a remote attestation. The archive is still fully
verified on the device. The common menu exposes option 4 only for this reviewed
bundle and only for a verified registration probe from the same archive/inventory.
It shows the new destination, capacity, review identity and write scope, then
requires a separate `1` before any placement writes. Canceling writes nothing.

This operation copies files into the fixed **preparation** slot only. It checks
current target/receipt/history identity, prefix absence (including aliases),
source/runtime identity, private parents and capacity; it rechecks under private
global/target and cooperative DroidDeck settings locks. Staging is bounded,
mode-preserving and verified against every archive member plus the six generated
metadata files. Native `renameat2(RENAME_NOREPLACE)` publishes the new tree;
post-publication verification repeats the probe and whole-tree checks. Existing
legacy trees are never repaired or replaced. A matching existing preparation tree
is observed read-only; a changed tree is refused. Failure preserves staging or
published data and its journal for inspection. The same target's normal plan is
then generated automatically, leaving later prefix/execution blockers in place.

The static scope is intentionally separate from full execution readiness. It
never calls Wine, wrappers, installers or the legacy sync helper, writes
compatdata, changes tool bindings, or asserts that other process namespaces are
stopped. Its writes are the new preparation tree/staging, private journal/locks,
DroidDeck's cooperative lock file and a new report. This is justified by the
absent new destination and the absence of any existing tool/prefix/config update.
The existing `apply_installation` API still requires all four independent full
readiness checks plus its `ProcessStopCheck`; it was not given bypass flags.
Only the private filesystem transaction is shared with the new scoped caller.
Runtime equivalence, GUI, stopped scope, dependency capacity and all execution
requirements remain unverified and cannot be satisfied by this placement report.

Exact confirmation pins the fixed target/destination/action, reviewed archive,
customizations and probe evidence. Available space is remeasured, not frozen into
identity; the already allocated staged tree is not counted a second time before
publication. A race creating the destination causes refusal without replacement.
The reviewed build identity is recorded in the output; it establishes which
artifact was copied, not source reproducibility or compatibility of Wine/games.


For the reviewed distribution's Xalia files, static placement may preserve a
small explicit `private_xalia_files` list of regular files with source mode 0666.
The list must exactly equal all otherwise unsupported entries in the pinned
inventory; no arbitrary writable path, directory, hardlink or other mode is
accepted. Every listed name is a direct `files/share/xalia/` file. This is not a
mode overlay: bytes and source modes remain unchanged. The private tool parent
must be owned by the current user and exactly 0700, checked before staging,
during filesystem guards and after publication. No chmod is applied to existing
parents. A parent becoming readable by others stops the operation. The original
full writer still has no such exception by default. This copy-only containment
must not be treated as execution readiness; future launch checks must establish
their own safe containment and all remaining runtime/process prerequisites.

## Read-only binding diagnostics (0.16.1)

If binding planning rejects an input after an installed tree has been verified,
the selection report preserves the installation, registration and prefix checks.
The binding subplan remains blocked. Independent bounded checks of the registered
tool, requested games, applied history, selection history and target mapping are
included with fixed diagnostic codes, without raw settings or exception messages.
These independent observations are not a coherent binding plan and cannot authorize
any writer. The existing strict binding validation and writer guards still apply.

Use the normal planning option to inspect an already placed tool. Reinstallation,
probe recreation and execution are unnecessary for this diagnostic step. Placement
success alone does not establish Wine execution, prefix initialization, dependency
installation or game compatibility.

## Preserving bounded Steam scalar values (0.16.2)

Steam config planning and candidate validation can preserve unrelated scalar values
longer than 4096 bytes within the existing 1 MiB file bound. Keys retain the 4096
byte limit; tool IDs, target IDs, depth, duplicate keys and quoted syntax checks
remain restricted. Other VDF readers retain their original scalar limit. Only the
target mapping is edited by the internal guarded writer, which remains unexposed.

For an installed tree, the read-only report compares the old scalar limit and the
preservation limit on the same bounded read. It records fixed rejection codes, byte
count and input digest, without settings values. These observations do not authorize
execution or settings writes. Every VDF rejection now has a fixed diagnostic code;
the local regression checks this coverage. Device validation of this change remains
separate from local fixture tests.

## Initialization input inspection (0.17.0)

When the selected tool is already fully verified, normal read-only planning also
checks the launcher hashes and literal settings restrictions, missing canonical
prefix and aliases, absent private work/home paths and their existing ancestor,
and two same-owner proc observations. It aggregates failures using fixed check
names and error classes without raw settings, process environment values or output.
No child is started, directory created, lock acquired or settings file changed.

This is input inspection for a future dedicated initialization test. Even a clear
process view cannot establish other namespaces or external launcher serialization.
The report retains explicit runtime, process-scope and growth blockers and never
authorizes execution. The existing launcher guards and CLI execution restrictions
remain unchanged. Prefix initialization, Wine GUI and dependencies still need
separate device validation after the test scope and changes have been shared.

## Batched observations and progress reporting (0.18.0)

The normal planning action includes the initialization input inspection and collects
independent filesystem metadata for Steam, tools, compatdata, settings and proposed
private work/state roots. It records available bytes/inodes, owner/mode and mount
read-only/noexec flags. These are observations, not actual write or execution tests.
Local X11 endpoint and authority-file metadata, known system executable availability,
and presence of selected runtime variables are collected without reading cookies,
exporting environment values, opening GUI connections or starting subprocesses.
The verified inventory also identifies the selected native Wine branch and inputs;
this is layout information, not runtime validation. No assets are executed.

Same-owner proc observations include fixed failure-stage counts and the peak counts
from two views, without PIDs, command lines or raw environments. Visibility and
serialization limitations remain unchanged. Independent context remains available
in an interactive error report even if target-dependent planning fails.

The JSON and terminal distinguish collected checks that passed, rejected checks,
observations requiring attention, dependent checks not run, deferred implementation
steps and unverified runtime limits. A legacy parser-limit refusal that the bounded
preservation parser handles is informational, not a new failure. The existing
blocked execution status is retained and is separate from the inspection summary.
This batch replaces the unrun 0.17.0 inspection; there is no need to run both.

## Dedicated first initialization trial (0.19.0)

A trusted distributed bundle can enable `initialization_trial: true` alongside its
reviewed build configuration. Menu 5 previews the new dedicated probe prefix,
private work/home, baseline plus 1 GiB reserve, journal and cooperative lock scope,
then requires a separate explicit confirmation. It runs only the reviewed preparation
tool's fixed `run cmd.exe /d /c exit 0`. It cannot execute a game, install assets,
change bindings or claim normal execution readiness. The default menu action remains
read-only. A reserve is an admission check, not a growth limit or filesystem sandbox.

The trial requires a matching private probe receipt, absent prefix and aliases,
absent trial paths, verified installed tree, reviewed source, shipped arm64 prefix,
live pinned runtime and two clear same-owner process views. Mutable legacy dist and
SteamPipe maintenance inputs are rejected. Reviewed Xalia modes remain subject to
the private 0700 tool-parent guard before and after launch. Snapshot runtimes are
refused. No readiness flags are fabricated for the ordinary LaunchSession API.

After confirmation the caller holds private global/target and cooperative settings
locks, refreshes the complete plan, creates private work/home and the new prefix,
and launches with the existing minimal environment/disabled observer and fixes.
Settings input hashes are compared before/after without exporting contents. Standard
input/output/error are DEVNULL. There is no raw registry or process-environment dump.
Waits are bounded, with up to five seconds of grace for lingering visible Wine
services. Timeout or residual processes retain `needs-user`; the operator can wait
again or hand off without a signal, deletion, automatic restart or adoption.

A zero command exit still requires the same payload/runtime/target and prefix version,
directories and registry headers. Result `initialized-unverified` does not establish
GUI, dependencies, templates or game compatibility. Trial records have their own
schema under `trials/` and appear in read-only management inventory with mandatory
reinspection. All partial prefixes, private directories and journals are preserved.

## Post-trial read-only audit (0.20.0)

Menu 6 reads an existing private trial record, then independently inspects the
current registration, prefix aliases, minimum prefix structure, metadata-only
prefix size, visible target process view and runtime context. It reconstructs the
expected tool from the pinned archive and trusted renderer, so a changed installed
tree does not prevent diagnosis. Strict verification remains unchanged.

The diagnostic comparison records bounded differences across known source members
and unexpected object boundaries, including modes, missing objects, content identity
and hardlink topology. Unknown names are hashed, their contents are never read and
unexpected directory subtrees are not traversed. The list is capped at128 entries
with explicit truncation. This comparison is diagnostic and cannot authorize a
writer or replace strict validation. Prefix sizing never follows Wine drive links.

If archive/runtime prerequisites are unavailable, independent prefix/process checks
still appear and dependent checks are explicitly marked not run. The private trial
record is read again to detect replacement and is never updated, adopted, retried
or promoted. Only a new result report is written. Future trial failures retain
fixed TreeMismatch metadata instead of only the exception class. An exit code zero
with a post-check failure does not become verified initialization automatically.

## Source-reviewed empty FEX directory and managed recheck (0.21.0)

Proton selects `files/share/fex-emu/` as FEX's local config directory. Pinned FEX
creates its `AppConfig/` directory during config lookup. `verify_tree` still rejects
extras by default. A separate runtime verifier permits only that exact directory,
absent from the source inventory, under an owned0700 tool parent, with an owned0700
empty directory and stable identity. Nonempty configs, links, other modes/owners,
other extras and modified source files are rejected. It never creates or removes
the directory. New dedicated trial post-checks use this narrow runtime contract.

Menu7 performs this verification and then offers a separately confirmed fixed
`runinprefix cmd.exe /d /c exit 0` for the existing managed trial prefix. It does not
initialize, clone, repair, install assets, modify bindings or rewrite old history.
It requires the private trial's prior exit0/unchanged-settings evidence, the original
probe receipt/current registration, reviewed source, current version and private
prefix/work/home ancestors, live runtime and clear same-owner process views.

Managed recheck plans carry a distinct trial origin and cannot be executed through
the ordinary LaunchSession readiness API. Rechecks have a separate journal and
inventory with mandatory reinspection. New result `probe-exited-unverified` means
only the fixed command and guarded postconditions passed; GUI, dependencies,
other-namespace stop scope and complete preparation remain unverified. Timeout
never kills a process or automatically retries. Old failed records remain intact.

## Measured dependency plans (0.22.0)

`--plan-dependency --assets <manifest> --asset-root <directory>
--dependency-handler softdenchi-interactive --dependency-asset <asset-id>` binds a
measured asset to a concrete handler plan without a registration or prefix write.
It is a separate read-only mode and returns2 for a produced blocked plan. No new
device action or installer execution is enabled by this mode.

The original interactive bootstrap is retained with no guessed silent arguments
or direct-MSI bypass, including its prerequisite handling. Product registration,
file hashes/PE/versions, UCManSvc configuration and both COM views must be checked;
exit0 alone is insufficient. MFC plans remain single-file candidates with an
unresolved architecture mapping, no broad vcrun6 install, CRT/OLE overrides or
substitution for MFC140. Original asset provenance, independent reference, terms,
identity and product-role blockers remain; executable handlers and live probes are
not yet connected. An unknown/partial/incompatible existing state never requests
automatic repair, upgrade or deletion. A persisted verified label never authorizes
a skip without live reinspection. Submitted postcondition observations are reported
separately and cannot authorize execution or binding.

## Managed-prefix SoftDenchi installation (0.23.0)

When the selection configuration contains `dependency_installation` (handler
`softdenchi-interactive`, recipe revision and one asset declaration), the short
launcher offers two more items for a managed trial prefix that already has a
successful fixed-command recheck:

- 8: interactive installation. A Wine builtin `winver` window is shown first. The
  original bootstrap starts only after the operator confirms the window appeared and
  the visible process view is clear again. The bootstrap runs from a new private copy
  under its distributed file name, with no arguments, no guessed silent switches and
  no MSI-only launch. The license is accepted, or not, by the operator in the
  installer window. No authentication is performed.
- 9: read-only reinspection without starting Wine.

The asset must be the exact bootstrap of the trusted, statically derived recipe in
`preparation_softdenchi_recipe.py` (SoftDenchi runtime 5.0.9.0, revision 1): a
self-consistent manifest for another x86 PE is refused. Terms and provenance
blockers still apply. Installation proceeds only when the live state is `absent`;
`partial`, `incompatible`, `present-unverified`, `present-verified` and
`uninspected` are preserved and reported. Nothing is repaired, upgraded, removed or
retried on another prefix.

The final state comes from an offline inspection after the visible process view is
clear: product registration and version, all recipe files (size, SHA-256, PE
machine), the UCManSvc service type/start/image, and the MSI Class-table COM entries
in the 64-bit and 32-bit registry views. Only recipe-listed keys and value names of
`system.reg` are interpreted; other data is not kept or exported, and `user.reg` is
not read. Links, hard links, special files and malformed or duplicated registry
data make an item failed or the whole state `uninspected`, never `absent`. Further product
traces (32-bit Uninstall view, Windows Installer product keys, UpgradeCode
relations) prevent `absent`; another product under the same UpgradeCode makes the
state `incompatible`. The registry must decode as strict UTF-8. A pending file
rename keeps the state unverified, and an unexpected value type makes it unknown. The Unix exit status is recorded only:
Windows exit codes such as 1602 or 3010 cannot be observed through it.

A new attempt is planned only after no record, a cancelled-absent or
stopped-before-installer record, a record that never reached the installer, or an
interrupted one; a failed or completed installer record, or any unreadable record,
blocks it for review. Prefix allocation is measured from metadata before and after
the installer and recorded with its growth.

Timeouts never kill a process; `q` leaves the child running and records
`needs-user`, not a cancellation. Records live in the private `dependency-installs`
journal and always require reinspection. Destination resolution follows standard
Windows Installer rules and is unverified on device Wine; registrations made by the
installer's self-registration step are not statically known and are not checked.

## Lingering SoftDenchi processes (0.24.0)

The SoftDenchi service is started at installation and can keep Wine running in the
managed prefix after the bootstrap exits. When the visible process view of that
prefix is not clear, the installation record and menu 9 keep a process inventory:
PID, start time, parent, a role (`wineserver`, `wine-infrastructure`,
`proton-xalia`, `softdenchi-service`, `softdenchi-proxy`, `other`) and the image
basename with a coarse place. Environment values, arguments and other paths are not
kept. `lsass.exe` and `tabtip.exe` count as Wine infrastructure only from the Windows
system directories; `xalia.exe` counts only as the selected tool's own
`files/share/xalia/xalia.exe` (its `Z:` or `\\?\unix` DOS forms, as given or resolved)
with an `explorer.exe` parent in the same view. Any other image ending in
`files\share\xalia\xalia.exe` is reported with the place `proton-share-xalia` but stays
unclassified and refuses the stop.

After an explicit confirmation, SIGTERM is sent only to SdProxy processes whose
parent chain reaches UCManSvc under `services.exe`, with consistent start times and
one shared executable identity (in menu 8 right after the installer run, also a chain
whose first SdProxy has no parent left in the view, if that SdProxy was observed as a
descendant of the installer process while it ran; see 0.26.3), from two identical inventories without unreadable,
unclassified or prefix-conflicting processes (both prefix variables, when present,
must name this prefix). The batch is pinned with pidfds and the full conditions are
evaluated again after pinning; before each further signal the view is read again
(after a bounded wait for the previous target to exit and for the view to settle; see
0.26.4) and anything new or unexplained aborts; each later target must keep its confirmed image,
prefix consistency and executable identity (only its parent may change). A target that
already exited is recorded as gone, and every per-target result is kept even when the
stop or a later step fails (0.24.1, 0.24.2). There is no SIGKILL,
no `wineserver -k` and no other process, prefix or game is signalled. If the view
does not clear within a bounded wait, the state stays `needs-user`. After a clear
view the installation continues with the offline post-inspection; menu 9 then
reinspects as before.

## Registered-game new prefixes (0.25.0)

With `game_preparation` (operator-declared profiles and recipes; only the SoftDenchi
recipe can be `ready`, MFC stays `blocked`; 0.27.0 adds read-only `game-folder-file`
recipes), menu 10 initializes a new prefix for a
registered game that has no compatdata yet. Probe registrations keep the dedicated
trial scope and existing prefixes stay read-only. The same guarded session as the
probe trial runs the fixed builtin initialization with the reviewed preparation slot;
records go to the private `game-prefixes` journal and bind the selected profile and
the measured game EXE (an undeclared EXE hash is recorded as an operator selection,
not as a verified edition). Dependency installation (menus 8 and 9) accepts these
records as well as probe trials; a changed game EXE refuses planning. Binding is not
written by these steps.

The preparation slot may hold FEX's one empty, owned, 0700 `AppConfig` directory:
when it exists, the reuse plan and the managed initialization/recheck launch plans
accept it under the source-reviewed FEX contract. Without it, or for the legacy slot,
the strict tree check is unchanged, and plans made under the contract are refused by
the ordinary launch readiness path.

## Target-only binding of a prepared game prefix (0.26.0)

Menu 11 binds one initialized registered-game prefix to the reviewed preparation slot
only when every dependency of the profile bound at initialization is live
`present-verified` (offline inspection with a clear process view before and after).
A `blocked` recipe (MFC today) or an unverified dependency is reported and nothing is
written. A profile changed since initialization refuses the plan (0.27.0 accepts only a later
revision of the same profile pinned to the initialized EXE hash; see below). After an exact
confirmation the existing guarded target-only writer changes this game's entries in
`games.json`, `config.vdf` and `state.json`, keeps other games' pending choices and the
default, and stores a private backup and record. Before each file write the
registration, the tool tree under the FEX contract, the prefix version, the stopped
view and the dependency state are checked again. No game is launched and no
authentication is performed; `preparation_complete` stays false until a normal launch
is verified separately.

## Binding later steps to the initialized prefix and registration (0.26.1)

A registered-game record now stores the created prefix root's directory identity
(device and inode, saved right after creation and before spawn) and digests of the
normalized registered EXE path and title. Dependency planning and installation,
binding plans, and the binding writer's readiness check require the live prefix to be
the same directory with the recorded version, and the registration to keep the same
path and title, so a restored or swapped prefix at the same path, or the same EXE
content registered from another folder, is refused. The readiness check before each
binding write uses the planning inspection itself, so a process observed during the
dependency inspection stops the write. A device-number change across reboots would
also refuse; that has not been measured on the device.

0.26.2 also records the identity of the WINEPREFIX (`pfx`) created by a successful
initialization and requires it at the same points, so swapping only `pfx` while the
prefix root and version stay is refused. Restoring files inside the same directories
is not detected by these identities.

## Stopping what the installer run left behind (0.26.3)

On the device (0.26.2) the bootstrap started SdProxy before UCManSvc and exited, so the
first SdProxy had no parent left in the prefix view, and `lsass.exe`, `tabtip.exe` and
Proton's `xalia.exe` stayed beside it. Menu 8 now records the start time of the process
it spawns for the installer (`installer.spawned_started`, from `/proc/PID/stat`) and,
while the installer runs, polls every 0.5 s: a SdProxy of this prefix whose same-owner
ancestry (PID and start time at every step) reaches that process is kept in
`installer.installer_proxies` (at most 64). In the same session only, a SdProxy chain
whose first SdProxy lost its parent is accepted when that first SdProxy is in this list
and the chain shares the executable identity of the one `services.exe` in the view. A
SdProxy started by any other launch, or one missed between polls, is not attributed and
refuses the stop. While the installer runs, menu 8 waits without asking for the first
10 minutes (in steps of up to 120 s), so the operator can work in the installer window
while the attribution keeps observing; after that it asks every 30 s as before. The
confirmation and the record state each target's origin
(`ucmansvc` or `installer-run`). All other conditions (two identical inventories,
nothing unreadable, unclassified or prefix-conflicting, pidfd pinning and revalidation,
SIGTERM only) are unchanged. Menu 9 keeps the UCManSvc-only rule because it has no
installer run to attribute the origin. The menu 10 profile prompt also accepts the
profile name.

## Sending to the second SdProxy after the first exits (0.26.4)

A stop could abort after the first SIGTERM because the view read before the second send
contained an unreadable process. The working hypothesis (not confirmed) is that an
exiting process is briefly unreadable (empty argv or a state change between reads). Now,
after each SIGTERM, the tool waits up to 5 s for the signaled SdProxy to exit (its pidfd
turns readable), then reads the view again every 0.25 s for up to 5 s until it is fully
readable and explained; only such a view allows the next send, and a target that has
exited meanwhile is recorded as gone. Reading again is allowed only while the view merely
shrinks (see 0.27.3 for the exact rule); anything new or changed aborts at once. If no
view qualifies, the stop aborts as before and the record keeps the unreadable PIDs of the
last view (`stop.unreadable_pids`, at most 16; process summaries also carry
`unreadable_pids`). Menu 8 prints why a stop was refused or aborted and how many
SIGTERMs were sent, and, when no post-inspection ran (`post_state` None or
`uninspected`), to restart DroidDeck and check the prefix with menu 9.

## Game-folder file dependencies and profile revisions (0.27.0)

Some games import a runtime DLL that their own folder already provides (for example an
x86 executable importing the ANSI `MFC42.DLL`), while the 32-bit MFC140 and VC++
2015-2019 runtime that SoftDenchi's in-process components load are installed by the
SoftDenchi bootstrap during menu 8. A new recipe handler,
`game-folder-file`, declares such a file by name, size, SHA-256 and PE architecture
together with the EXE hash and import it was derived from (the import must name the
file); the profile must pin that EXE hash. It is the only handler besides the SoftDenchi
installer that may be `ready`, so a bound prefix no longer implies a verified SoftDenchi
unless the profile lists it. Menu 11 checks it read-only: exactly one single-link
regular file of that ASCII name (case-insensitive) directly in the registered EXE's
folder, matching size, hash and architecture, and of the same architecture as the
registered EXE, is `present-verified`; none is `absent`; a symlink, several case
variants, other content, another architecture or a change while reading is
`incompatible`; unreadable is `uninspected`. `present-verified` means a match with the
declaration only: the file's provenance is not checked and the EXE import table is not
read. The check runs again in the readiness callback before each binding write. Nothing
is copied, moved, installed or loaded; whether the game loads the file is only
observable at launch. `mfc-local` (placing MFC into the prefix) stays blocked.

Menu 11 also accepts a later revision of the profile bound at initialization: same
profile ID, a strictly higher revision, and a pinned EXE hash equal to the one measured
at initialization (which the recheck still verifies live). Dependencies are evaluated
live, so a new prefix is not needed. The record keeps no dependency list, title or
edition, so a revision that drops a dependency or renames the profile cannot be detected;
menu 11 shows the current title, edition and dependencies for the operator. The plan
and result record both revisions and digests; any other change still refuses.

Menus 10 and 11 report whether the registered EXE path is ASCII and warn otherwise: a
game in a folder named with non-ASCII characters has been seen to exit right after start
while an ASCII-named copy with the same kind of prefix proceeded (the cause is not
known). The registration path is fixed at initialization, so a folder must be renamed
and registered again before menu 10.

## DroidDeck's redistributable markers in the preparation slot (0.27.1)

DroidDeck, in its first game session after a compatibility tool appears, appends Steam
CommonRedist "installed" flags (DirectX, .NET 4.5.2, VC++ 2017/2019/2022) and VC++
runtime version keys to the tool's `files/share/default_pfx_arm64/system.reg` (keeping
its mtime) and adds `.droiddeck-redists` and `.droiddeck-redists-checked` beside it, once
per tool. After that, every step that verified the preparation slot stopped.

The runtime-contract verifier (`verify_fex_runtime_tree`, used by the reuse plan of the
preparation slot when its FEX directory exists, and directly by trials, recheck,
dependency steps and binding) now accepts this bounded change in addition to the FEX
directory: the archive bytes of that `system.reg` must remain a byte-for-byte prefix with
the same mode, followed by at most 8 KiB starting and ending with a newline, made only of
sections `Software\[Wow6432Node\]Valve\Steam\Apps\CommonRedist\<part>\<part>` with
`dword` values and `Software\[Wow6432Node\]Microsoft\VisualStudio\14.0\VC\Runtimes\{x86,x64,arm64}`
with `Bld`, `Installed`, `Major`, `Minor`, `Rbld` (`dword`) and `Version` (`"v<digits/dots>"`),
each section with at least one value; such a tail requires the `.droiddeck-redists`
marker. The two markers must be small single-link regular files without execute or
group/other write bits; their content is only hashed and reported. Failures carry a
located tree diagnostic (`redist-registry-tail`, `redist-marker`, `redist-marker-missing`).
The ordinary strict `verify_tree` is unchanged. Proton copies the template, including
the tail and the markers, into each new prefix; whether that makes the SoftDenchi
bootstrap skip its VC++ runtime is not verified, and the SoftDenchi post-inspection
does not check VC++ runtime files.

## Review fixes (0.27.2)

- Stop: a fresh view is read before every later SIGTERM, also when the previous target
  had already exited at its send (0.26.4 skipped the read in that case). An abort
  records `revalidation` (`timeout` or `not-shrinking`, number of reads, the target,
  PIDs not in the confirmed view, counts of the last view); each later signal entry
  records its reads and the unreadable PIDs seen while settling.
- Binding: each dependency state carries its recipe revision and digest, and a
  `game-folder-file` state also its declared file, so the plan digest and the result
  change when a recipe changes under the same dependency ID.
- Tool template: the accepted DroidDeck redist state (sections, appended bytes, tail
  SHA-256, marker hashes) is reported as `tool_droiddeck_redist` (renamed to
  `tool_runtime_writes` in 0.27.4) in the reuse plan, the
  menu 10 preview, the recheck plan and the binding plan, is part of their digests, and
  the recheck readiness check and the binding readiness check before each write require
  it to be unchanged (the menu 10 initialization guard re-verifies the tree but does not
  compare this state).

## Review follow-ups (0.27.3)

- Stop: while settling, a readable process counts as unchanged only if it is in the
  confirmed view with the same image, prefix consistency and executable identity (its
  parent may change); otherwise the stop aborts at once (`not-shrinking`). Menu 8 shows
  the number of SIGTERMs whenever any was sent; menu 9 shows the restart hint only when
  its inspection is `uninspected`.
- Binding: non-object recipe entries are refused by validation; ready handlers are
  dispatched explicitly.

## CPython caches written into the preparation slot (0.27.4)

Once a game is bound to the preparation slot and launched, CPython writes bytecode caches
for the tool's own modules (for example `__pycache__/user_settings.cpython-314.pyc` and
`protonfixes/__pycache__/*.pyc`) into the slot, after which every strict tree check
stopped with `unexpected-object`. The runtime-contract verifier now also accepts a
`__pycache__` directory (no group/other write) only in an archive directory that holds
reviewed `.py` sources, containing only `<stem>.cpython-3NN.pyc` for a `<stem>.py` of the
archive in that directory: single-link regular files without execute or group/other write
bits, at most 16 MiB and 256 per directory, timestamp-based (flags 0) with the source
mtime and size of the installed, verified source. Anything else in it, a cache elsewhere,
or a changed source is refused with a located `python-cache` diagnostic.

This weakens the tree check: the bytecode is hashed and reported but not compared with
the source, so a cache rewritten with a matching header would run instead of the
reviewed source. Only a process of the same user can write there, and such a process
could also change the sources, which the check still detects. The ordinary strict
`verify_tree` is unchanged.

The accepted state (DroidDeck redist markers and the caches) is reported as
`tool_runtime_writes` in the reuse plan, the menu 10 preview, the recheck plan and the
binding plan, is part of their digests, and the recheck and binding readiness checks
require it to be unchanged; a game launched from the slot between planning and writing
therefore stops the step.

## Tool launches do not read the slot's bytecode caches (0.27.5)

Accepting caches by header (0.27.4) also meant that the tool's own Proton launches
(initialization, recheck, dependency steps) imported cached bytecode that is not compared
with the reviewed sources. Every tool launch now sets `PYTHONPYCACHEPREFIX` to an absent
path in its private work area (with `PYTHONDONTWRITEBYTECODE=1` nothing is written there),
so CPython compiles the verified sources instead of reading `__pycache__` in the tool.
The plan refuses if that path exists, and each spawn checks again that it is still absent.
Game launches by DroidDeck are not affected and keep the weakening described in 0.27.4.
Standard-library caches are not used by these launches either, which may make them
slower.

## Cache rule refinements (0.27.6)

- Cache names: the module stem may start with a digit or contain `-` (per-game fix
  modules use such names); it must still be a `.py` of the archive in the same
  directory.
- Header: the magic must end with `\r\n`; a cache tagged for the verifying interpreter
  (`sys.implementation.cache_tag`) must carry its magic number. Caches of other CPython
  versions are accepted by header and hash only, since CPython does not read them.
- Cache bytes count toward the installed-size bound.
- Diagnostics name the failing field (`pyc-magic`, `pyc-flags`, `source-mtime-or-size`,
  `source-missing`) with the cache's location.

Recovery: a stop with `python-cache` (for example a stale cache after the sources were
copied without their mtimes, a leftover temporary file after an interrupted write, an
`-O` cache, or group-writable files) is cleared by removing the reported `__pycache__`
directory of the slot; launching a game from the slot once recreates valid caches. Tool
launches never write them (`PYTHONDONTWRITEBYTECODE`, 0.27.5).

## Final-review fixes (0.27.7)

- Stop: before every later SIGTERM the view must only have shrunk relative to the
  confirmed view (no new process, no changed image, prefix consistency or executable
  identity, no unreadable PID outside it), also when the view would otherwise pass the
  stop conditions (for example a restarted service or another launch); otherwise the
  stop aborts at once (`not-shrinking`).
- Menu 10: the initialization guard right before spawn requires the runtime writes of the
  preparation slot (`tool_runtime_writes`) to equal those of the plan.

## One-pass preparation of a new game (0.28.0)

Menu 12 runs the steps of menus 10, 8 and 11 for one registered game in one run, with one
confirmation. It is offered when the bundle enables the initialization trial, the
reviewed placement, game preparation and dependency installation.

- Selection: registered games without a prefix ("new") and games with a tool record
  ("resume"). A profile is chosen automatically when exactly one profile pins the
  measured EXE hash; otherwise it is asked as in menu 10.
- Confirmation: before anything is written, the run shows the registration, profile,
  prefix, preparation slot, the SoftDenchi installer with its silent arguments, the
  license statement, the SdProxy stop rule and the settings files the binding changes.
  The confirmation is taken for a digest of fixed values (registration and EXE, profile
  and recipe digests, asset and installer mode, private paths, payload/customization/
  runtime identity and runtime writes, binding plan digest including the settings
  inputs). Each later step plans again (the same plans, guards and writers as the
  separate menus) and stops, without asking again, when its fixed values differ.
- Locks: the private tool/prefix lock is held from the first write to the last step;
  the DroidDeck settings lock is held during initialization and installation only, and
  the binding writer takes it itself.
- SoftDenchi: the recipe bootstrap runs with pinned silent arguments
  `/s /v/qn /vREBOOT=ReallySuppress` (InstallShield Basic MSI setup.exe; `SILENT_LAUNCH`,
  bound to the bootstrap hash and kept out of the recipe digest). There is no winver
  check; the record states `gui_check.status = not-applicable`, `installer.mode = silent`
  and `license_consent = one-pass-confirmation`. Menu 8 keeps the interactive installer
  and its display check. A lingering SdProxy is stopped under the unchanged rules,
  confirmed by the one-pass confirmation (`stop.confirmation = one-pass-preapproved`).
- Interactive fallback: only when the silent run installs nothing (`cancelled-absent`),
  the run plans the interactive installer, requires every fixed value except the
  installer mode to be unchanged, and asks for a separate confirmation of that plan.
- Resume: a stopped run is continued by running menu 12 again. A failed or unreadable
  installation record stops; a record after which a new attempt is allowed leads to an
  installation when the current state is `absent`; `present-verified` (current, offline
  inspection with a clear view) moves on to binding. Moving on from a record whose
  post-inspection never ran is recorded as a separate read-only check. Partial, unverified
  or incompatible states stop and nothing is repaired.
- Before the confirmation (nothing written yet): a profile dependency that is not
  `ready` stops; for a new prefix the installer file is inspected and bound to the
  recipe bootstrap; binding records are read (any tool version, shape checked) so an
  unreadable one stops here. Unreadable game prefix records are counted and shown but
  do not hide other registrations.
- Binding: decided by the current three settings files, after the dependencies (an
  unverified dependency stops even for a bound game). All files bound: reported as
  bound. Some bound: stops. None bound: binds, unless an earlier binding of this game
  was verified or wrote files.
- Result: the fixed values are kept per item (digests); a stop names the changed items.
  Each step keeps its plan summary and record, also when an exception interrupts it.
- Not done: registering the game, authentication and the first launch. Silent
  installation on device Wine is not yet measured.

## One declared DLL in the prefix: handler `prefix-dll` (0.29.0)

A recipe with handler `prefix-dll` places one x86 DLL into the initialized game prefix's
`pfx/drive_c/windows/syswow64/`, as menu 12's step between the initialization and the
SoftDenchi installation. A profile can then declare a runtime DLL that the game imports
without pinning the EXE hash or asking the operator to put the file into the game
folder. `mfc-local` stays reserved and blocked.

- Declaration: the recipe carries an asset declaration in the manifest format and
  `"destination": "syswow64"`. A ready recipe requires an x86 PE, a reviewed provenance
  and `personal-use-reviewed` terms, a known size and an independent SHA-256 reference.
  The file name is a single short ASCII basename ending in `.dll`; it is placed in lower
  case, and two DLLs of one profile may not share a destination name. The asset file is
  read from the folder of `prepare.sh`, like the SoftDenchi installer.
- Not changed: registry, DLL overrides, registration (regsvr32), the game folder, and any
  existing file (never overwritten, replaced or removed). Wine is not started.
- Refused: a name that the selected payload ships under `files/lib/wine/` or
  `files/share/default_pfx*/` (a native copy would hide the builtin); a `syswow64` whose
  x86 layout cannot be confirmed. The layout check reads `syswow64/kernel32.dll`, which
  must be a link resolving to the verified payload's `files/lib/wine/i386-windows/kernel32.dll`
  (compared by file identity, not by the spelling of the link) or an x86 regular file; `system32` is not used, since on ARM64 devices it holds ARM64 and x64
  images.
- State (read-only): `absent`, `present-verified` (exactly one single-link regular file
  whose size, SHA-256 and PE architecture match the declaration), `incompatible` (case
  variants, links, other content, a Wine builtin or placeholder file), `uninspected`.
  `present-verified` is a match with the declaration only; whether the game loads the
  file is observable at launch. Menu 11 and the binding step include it in the
  dependency check and in the readiness callback before each settings write.
- Copy (0.29.1): under the private and DroidDeck locks, with the managed recheck guard and a
  clear process view. Every step works relative to one opened `syswow64` whose device and
  inode are part of the plan. The plan digest (which includes the latest record) is compared
  before this run writes its own record; afterwards the running guard applies. The asset is
  read into memory once and checked (size, SHA-256, PE architecture) before anything is
  created. The destination name is then created with `O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW`
  (an existing name is never replaced); its device/inode is recorded as `created` right
  away, with SIGINT/SIGTERM blocked between the creation and that record. The content is
  written and read back through the same descriptor. Nothing is ever removed, renamed,
  truncated or written again later. (0.29.0 named an `O_TMPFILE` file through
  `/proc/self/fd`; that failed on the device with errno 95.)
- Records: `prefix-dlls` (phases `planned`, `created`, `present-verified`, `failed`; 0.29.0's
  `linked` is still read). A failure before the creation ends `failed`; after it the phase
  stays `created` and the error names the step (`read-asset`, `create`, `record-created`,
  `identity`, `write`, `fsync-file`, `read-back`, `fsync-directory`, `post-inspection`). The
  asset is limited to 64 MiB.
- Resume: the latest record of the same initialization, dependency and destination decides
  with the current state. A destination matching the declaration is accepted whatever the
  phase. An absent destination is created after no record, `planned`, `failed` or `created`,
  and stops after `linked` or `present-verified` (it disappeared). A partial file left by an
  interrupted write (`created`) is never written again, since inode numbers can be reused
  across runs; the run stops and the operator removes it. An empty file left between the
  creation and its record also stops. A replaced `syswow64`, a record for another recipe or
  asset (the recipe must stay unchanged to continue 0.29.0 records), or an unreadable record
  stops.
- Menu 12: the confirmation lists each DLL (name, asset hash, destination); the fixed
  values gain `dlls` (recipe digest and measured asset per DLL); a missing or different
  asset stops before anything is written, also when resuming a game whose DLL is already
  placed (the asset is part of the confirmed values). On resume, a profile that changed
  since the initialization (other than an accepted later revision) stops before any step.
  The plan observes the process view before and after inspecting; an unclear view stops.
- Not measured on a device: the 0.29.1 creation in the prefix's `syswow64`, loading from
  `syswow64`, and whether the file stays through Proton updates.

## Operational entry (0.30.0)

When a bundle enables the probe material, the reviewed placement, the initialization
trial, dependency installation and game preparation (the conditions of menu 12), the
first screen offers four entries. A bundle missing one of them keeps the earlier screen.

```
1. 新しいゲームを準備（初期化→DLL→ソフト電池→割り当て。途中からの再開も可）
2. ゲームの状態を確認（何も変更しません）
3. 新しいProtonを準備用slotに置く（起動しない）
4. 詳細メニュー（検証用・手動の操作）
```

- 1 is menu 12. 4 shows the earlier menus 1–12 with their numbers unchanged. Any other
  input, including a number of the earlier screen such as 12, cancels without writing.
- Guidance follows the screen: with the entry screen it names "詳細メニューの9" and
  "もう一度 1"; bundles with the earlier screen keep "メニュー9" and "12".
- 3: placement without a probe. An ordinary registered game (not a probe EXE) is used
  only to confirm the registration source and the executable DroidDeck records; its
  prefix, settings and files are only read, and a prefix may exist. Exactly one
  registration must point at the executable; registrations with two prefix aliases, a
  symbolic-link prefix, or a game folder that contains or lies inside Steam, the DroidDeck
  settings or the tool store are listed with
  the reason and cannot be chosen. The plan carries `confirmation_registration` instead of
  `probe_registration`, and the witness kind is part of the confirmed digest. Placement
  itself (review, staging, full tree check, non-replacing publication, locks) is
  unchanged and creates no follow-up plan. Menu 4 still requires the probe and an absent
  prefix.
- Reads from the asset folder (`prepare.sh`'s folder) do not compare timestamps: the
  payload archive for registered games (planning, staging, managed recheck), declared
  assets (installer, DLLs) and the source of the installer copied into the private cache
  (`cache_asset` stays strict for other callers such as `--stage-local`). Every byte is still hashed
  against the declared size and digest, a size or identity change still stops, and the PE
  architecture is taken from the hashed bytes. Shared storage was seen to change file
  times while reading. Probe trials, private records, Steam and DroidDeck settings,
  installed trees, the game EXE and prefix registry reads stay strict.
- 2: the state of each game this tool initialized, read-only. No locks (neither the
  private store locks nor the DroidDeck settings lock), no store creation, no Wine and no
  SdProxy stop offer; only the result JSON is written. The payload is read once and its
  inventory is passed to every game's checks; a missing payload or an unplaced slot is
  reported once and leaves dependencies undetermined. Per game: the initialization record,
  the profile, the assignment from `games.json`, `config.vdf` and `state.json` (this
  bundle's slot, another Proton by name, none, partial with the differing files, or
  another Proton whose three files disagree), the dependency states, and the next step.
  A game assigned to another Proton is out of this bundle's scope. A running game, or a
  read that changed underneath, is shown as not checkable. Problems of one game do not
  stop the others.
- The next step comes from the read-only evaluation that menu 1 uses before its
  confirmation (`evaluate_resume`): the pre-write stops (profile and revision, blocked
  dependencies, DLL assets, the installer of a new prefix, binding records) and each
  step's decision (DLL resume, SoftDenchi state and installation plan, binding). The space
  check of each later step counts the bytes the earlier steps of the run write (a DLL before
  the installer; recorded as `capacity_after_earlier_steps`), and one SoftDenchi
  installation satisfies every dependency it handles. "Ready" means every dependency is verified and the game is bound. When resuming, menu 1 now
  stops before its confirmation, with the same stage and reason, when a later step would
  stop (for example a binding that cannot follow because a game-folder file is missing),
  instead of writing the earlier steps first. Each step still plans again under its locks.
- Stops and lists: a stop caused by an input that changed while it was read records
  `reason: input-changed-during-read` and the names of the differing fields
  (`changed_fields`) in entry 3, menus 1, 4, 7 and the probe material. Menu 1's list shows
  the current assignment name of each game it can resume. For a game assigned to another
  Proton, menu 1 stops when this tool's records show an earlier verified binding (or one that
  wrote files); otherwise it binds the game to this bundle's slot after the confirmation.
  When resuming and the game or Wine is running, menu 1 stops before its confirmation and asks to end them first. The resume
  evaluation reuses the payload inventory read for the confirmation (one archive read).
  Entry 3 lists two registrations of one executable as ambiguous and keeps the excluded
  candidates and their reasons in the result.

## Proton update and the batch first screen (0.31.0)

With the operational conditions of 0.30.0, the first screen now lists what this bundle
would do and runs it after one confirmation. 0.30.0's four entries are under 3 with the
same numbers, followed by two new ones.

```
1. すべて実行する            (only when something is listed)
2. ゲームの状態を詳しく見る（何も変更しません）
3. 個別の操作                (1-4 of 0.30.0, 5 move a game, 6 assign a game to another slot)
```

- The list is read-only (no locks, no store creation, no Wine), built with the status
  check's global payload/slot check and menu 1's own planning (`interactive_one_pass`
  with `mode="plan"`). It shows "to do" items: place the bundle slot, save the slot's
  verification data, move or align games, resume, prepare new registrations; and "not
  done" items with their reason. Registrations with a prefix but no record of this tool
  are grouped once (the tool never adopts an existing prefix). New registrations use the
  only profile without a pinned EXE hash; non-ASCII EXE paths are left to entry 1. When a
  SoftDenchi installation is listed, the installer name, hash, arguments and the licence
  sentence are shown; "1" includes that consent and the SdProxy SIGTERM rule of menu 8.
  To read the licence on screen, the list points to detailed menu 8 (after menu 10 for a
  new game). Moves and alignments are planned read-only with the run's own move plan; a
  move that plan would stop is listed under "not done" with its blockers, and the status
  check shows the same dependencies and blockers. "Not done" reasons are shown in words
  (the status check uses the same text) with menu 1's next step when it has one; a resumed
  game lists what it will do; saved slot data that differs, cannot be read or was saved
  under other rule versions is listed under "not done" (never rewritten). The payload is
  read once for the whole list.
- Without the bundle slot only the placement is listed. It is done with an automatically
  chosen confirmation registration (registrations assigned to a preparation slot first,
  then by number); only a registration-specific failure tries the next one. The screen
  names the registration used and the state of the slot data; when no registration can
  confirm, the skipped registrations and their reasons are shown and saved with the advice
  to register one game first. The list is then built again and confirmed a second time.
- Running: each step plans again under its own locks. Before a game starts, its entries
  in `games.json`, `state.json` (`games_applied`, and its part of `auto`, `picked`,
  `native_choices`) and `config.vdf` must be the listed ones; menu 1 additionally compares
  its fixed values (except the whole-file binding digest) and stops when more actions are
  needed than confirmed, when the kind (new or resume) differs, or when a step under the
  lock would write something not confirmed; the listed entries are compared again under
  the lock. A game stopped before writing is skipped; a stop after a game started writing,
  or a failure not about that game (opening the private store or taking a move's lock),
  ends the run. A failure to save the slot data is reported and the run goes on.
  Outcomes per game: done, not started, stopped before writing, partially applied. A
  partial game names the stage it stopped at, and the binding backup only when it exists.
- Progress (`batch-runs/`): before a step writes, the record ID it uses (`trial_id`,
  prefix DLL `record_id`, `install_id`, `binding_id`) is saved with the locked store of
  that step. The next first screen reconciles an unfinished run from those IDs, the
  private records and what was made under them before a record (an installer input
  folder, binding backups; a binding note alone counts as nothing written). An unfinished
  binding whose changed files all hold their new bytes (compared with the note's hashes) is
  shown as "only the final check is missing". Runs are marked reviewed when a new run
  starts. The result JSON keeps each game's menu 1 report and journaled IDs and is
  rewritten whenever an ID is recorded and after every step (private copy and one shared
  copy, atomically).
- Moving (operation 5, and the batch run for slots listed in the bundle's `supersedes`):
  only games consistently assigned (all three files, compared by `valve`, `dir` and the
  tool ID) to another preparation slot this tool placed (an `installed-tree-verified`,
  published installation record of any tool version; the folder registered with the same
  tool ID). Dependencies must be verified, the prefix version must equal the bundle
  Proton's `CURRENT_PREFIX_VERSION` (read from the payload), and no game or Wine may run.
  The x86 layout check accepts a link into such a slot only for this judgement
  (`previous-slot-link`); writing paths (prefix DLL placement, SoftDenchi installation,
  including `winver`) require a link into the bundle slot or an x86 regular file. A
  DroidDeck screen choice of the bundle slot whose other two files still name the old slot
  is aligned without rewriting `games.json`; the reverse direction is never written.
  Games returned from this slot, or with a missing supplementary record, are moved only
  one by one. Games whose records or settings cannot be read are listed with the reason
  instead of being left out.
- Supplementary records (`binding-notes/`): written before the binding record, with the
  slots involved, the per-file before/after hashes and, for operation 6, the cache move.
  Binding records keep their 0.30.0 shape, so earlier tools still read the store.
- Slot verification data (`slot-manifests/`, up to 32 MiB, written once per slot name and
  never replaced): the payload inventory, the expected generated files and the rule
  versions, saved when this tool verifies the bundle slot (placement, reuse, the batch
  run). A different or unreadable record makes the slot unusable for operation 6. The same
  contents saved under other rule versions are reported as such ("rules-differ"), not as
  another slot; a later version decides how to save them again.
- Operation 6 assigns a game currently on the bundle slot to another slot with saved data
  that still verifies. It does not need the bundle slot to be intact and does not check
  dependencies or the bundle payload; it checks the initialization record, the game
  EXE, the prefix, the target slot (registered tool, saved data, prefix version) and that
  no process uses the target slot (executable, working directory or a path argument; the
  launcher is a Python script), and its placement record again at writing time. Slots that
  are not targets are shown with the reason and the manual route (the DroidDeck screen and
  the sync command); dependency states are shown but never required. Only the
  `__pycache__` directories the verification accepted are moved into
  the private store (`slot-caches/<binding_id>/`, non-replacing renames, never deleted)
  before the files are written, so the next launch rebuilds them from verified sources;
  their contents are not compared. The binding writer has a separate `revert` kind whose
  readiness keys are only what is checked; a normal binding can only assign the bundle
  slot and a revert never can. The bundle slot and the supplementary-record callback are
  required arguments of the writer.
