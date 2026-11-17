# Private local staging (0.2.0)

This is preparation infrastructure, validated with synthetic files. It does not
install a runtime or prepare a prefix. The operator-declared profile, asset
provenance and compatibility assertions are not promoted to device verification.

`--inspect` / `--plan` remain read-only, including when `--assets` is supplied.
The separate `--stage-local` mode writes only an explicitly chosen management
root. `--list-local` reads an existing root without creating files or taking locks.
No mode invokes subprocesses, network access, archive extraction or installers.

## Asset input

Supply `--assets /test/assets.json --asset-root /test/sources`. The manifest is a
strict JSON object with `schema_version: 1` and an `assets` array (1–128 entries).
Unknown fields, duplicate IDs/keys, unsafe filenames and invalid values are rejected.
All listed fields below are required; nullable fields must explicitly be `null`.

| Asset field | Contract |
| --- | --- |
| `asset_id`, `revision` | Restricted ASCII ID and positive integer, independent of schema/tool version |
| `version`, `purpose` | Declared version and intended use; version resources inside a PE are not inspected |
| `filename` | Relative input path within the explicit source root; no absolute path, `..`, symlink parents or `.env` files |
| `format` | `pe` or `opaque`; neither is executed or extracted |
| `pe_machine` | `x86`, `x86_64`, `arm64` or `null`; must be `null` for opaque inputs |
| `expected_size` | Positive exact byte length or `null`; cannot exceed the trusted format ceiling |
| `expected_sha256` | Lowercase SHA-256 reference or `null` |
| `hash_kind` | `unknown`, `local-measurement` or `external-reference` |
| `hash_reference` | Description of the reference hash's evidence or `null` |
| `source_kind` | `unknown`, `official` or `game-bundled` |
| `source_reference` | Provenance reference, separate from the hash reference |
| `acquired_on` | Canonical `YYYY-MM-DD` date |
| `provenance_status` | `unconfirmed` or `operator-reviewed` |
| `terms_status` | `unconfirmed` or `personal-use-reviewed`; no redistribution authorization is implied |

PE files have a trusted input ceiling of 512 MiB; opaque inputs have a ceiling of
2 GiB. External JSON cannot increase them. These are input limits, **not archive
expansion limits**. No extraction recipe has been enabled. JSON/record/output size
limits remain 1 MiB; string size 4 KiB and nesting depth 16.

Read-only inspection distinguishes missing assets, reference hash/size/architecture
mismatches, unconfirmed provenance/terms and a locally measured hash without an
independent reference. A hash match establishes byte identity; the tool cannot
authenticate an operator's provenance or legal assertions.

Staging requires every listed asset to have reviewed provenance/terms and an
independent reference hash, exact length and (for PE) architecture matching the
measured file. A locally measured hash alone is insufficient. It stops before
creating a store when these asset preconditions fail. Passing them enables only
private caching; all prefix recipes remain blocked.

## Commands and write scope

Start with the inspection command in [README](README.md), adding the manifest and
source root. To opt into local staging, replace the mode with `--stage-local` and
add `--management-root /test/private/store`. Supply the selected `--app-id`,
`--exe-root`, `--profile` and `--recipes` as well as the registration/settings inputs.
The parent `/test/private` must already exist. Paths here are synthetic examples,
not a device deployment procedure.

The store must be a dedicated private directory disjoint from the Steam,
DroidDeck settings, EXE and asset source roots, and all input files. There is no
default management root. The tool creates only the root itself (0700), then:

```text
store.json                         # Store schema/application marker (0600)
locks/global.lock                  # Persistent flock files (0600)
locks/prefix-<compatdata-hash>.lock
assets/<asset-id>-r<revision>/      # Private directory (0700)
    payload.bin                    # Copied bytes (0600, never executable)
    receipt.json                   # Validated copy's metadata/identity marker
runs/<run-id>.json                  # Private atomic journal (0600)
```

Existing directories/files are checked for ownership, permissions and unexpected
links; they are not chmodded into compliance. An existing root without the exact
store marker is accepted for initialization only if it is empty and private.
Managed writes use directory file descriptors, `O_NOFOLLOW`, exclusive creation
and bounded names. Root and lock-file identities are checked again before writes.
These checks do not isolate a Windows installer or defeat all interference by
another process with the same OS privileges.

Assets are copied from an opened regular file, with source-change detection, then
the **copied bytes** are independently reread and checked. The receipt is written
only after those checks. Any failure before it leaves an incomplete object; an
invalid or interrupted receipt is rejected. Reuse always rereads the payload and
checks the current manifest against the receipt. The same asset ID/revision cannot
silently acquire different bytes or metadata. A pinned cache is a separate copy,
not a hardlink to the original.

## State, interruption and resumption

A run records its tool version, profile/recipe/asset revisions, asset hashes and
metadata digests, EXE identity, canonical target key, input digests, declared
compatibility, timestamps, attempts, check IDs/results and exit codes. There is no
raw environment, config, authentication registry or installer log in the journal.
`template` is `null`; `preparation_complete` is always `false` in this version.

Steps use `pending`, `running`, `succeeded`, `failed`, `needs-user`. A zero exit code
alone cannot produce success: a trusted check callback must return nonempty passing
postconditions. The current pipeline can succeed only at `asset-cache`, then pauses
`prefix-preparation` as `needs-user` without initializing it. It exits **2**, which
means preparation remains blocked, even after the cache step has succeeded.

Journal writes flush/fsync a new private file, compare the previous raw digest,
reinspect plan inputs immediately before commit and atomically replace only the
unchanged prior record. A conflict or failed write does not overwrite another
update. No whole-setting rollback, authentication reset or prefix deletion exists.

To inspect remaining objects:

```bash
bash prepare-game.sh --list-local --management-root /test/private/store
```

The inventory reports stored run status with `reinspection_required: true`; it
does not turn a saved success into verified preparation. It reports incomplete or
invalid cache objects and invalid journals separately. Inventory reads/hash checks
can take time for large caches. Interrupted temporary JSON files are listed.

To resume a run, repeat the **same staging inputs** and add `--resume-run <RUN_ID>`.
Loaded runs cannot transition until reinspection has converted interrupted
`running` steps to `needs-user` and rechecked any saved successes. Missing/modified
cached files fail reinspection, rather than being accepted from a success marker.

Resumption requires the original declared inputs, including source files, to remain
available and unchanged. If configuration, EXE, manifest or source assets have
changed, the old run is refused: inspect a fresh plan. A valid cached copy can be
verified independently with the inventory; fallback to cached inputs when the
original source disappears is not implemented in the staging CLI.

Incomplete or invalid cache slots are retained and never overwritten or deleted
automatically. They cannot be repaired by rerunning this command. Inspect their
identity/status first; a separate explicit cleanup/recovery operation is still to
be designed. For another synthetic test, use a new empty private test root and
retain the original failure evidence. Ordinary shutdown removes only the tool's
own transient atomic-JSON file; a crashed process may leave it for inventory.

## Locks and remaining boundaries

Mutation takes nonblocking locks in the fixed order **global → target prefix key**,
within the same management root. Contention stops immediately; exceptions or process
exit release the OS locks. Lock files persist and are never deleted to force entry.
Removing/replacing a held lock makes later mutation checks fail.

All invocations for a target must share the same management root. These locks do
not coordinate independent roots and do not block normal DroidDeck/Wine launches.
DroidDeck's settings lock, process-stop verification and final synchronization are
not implemented or invoked. No state marker is written into compatdata itself.

Device execution, trusted payload/helper hashes, concrete runtime postconditions,
asset-to-recipe binding, extraction policies, final binding/synchronization and
prefix/template operations remain future work. Local tests establish behavior of
the synthetic workflows, not compatibility with an actual device or installer.
