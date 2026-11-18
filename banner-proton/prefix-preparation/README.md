# Prefix preparation: offline planning and local staging (0.6.0)

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

No CLI mode launches Wine, executes DroidDeck helpers or `user_settings.py`, installs
dependencies, downloads, extracts archives to disk, registers Proton, synchronizes settings,
or creates/modifies a game prefix. An internal initialization/probe launcher exists,
but is not connected to the CLI or executable recipes. It requires a complete pinned payload inventory, pinned registration/EXE and
scoped proc observations, plus caller checks for provenance and runtime/stop scope.
Local tests use a harmless substitute, not Wine. Launch records now use schema 2;
schema-1 launch records are incompatible and are not migrated.
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
real readiness checks. Executable recipes, new-tool registration, final engine
integration and template cloning remain pending. Device
validation has not been performed for this tool.
