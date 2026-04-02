# JA4 Hash Input Debug Mode Design

## Summary

Add an explicit CLI flag, `--debug-hash-inputs`, to both `pcap` and `live` modes so operators can inspect the normalized strings that feed the JA4 `cipher_hash` and `ext_hash` calculations.

The default output contract remains unchanged. When the flag is enabled, each emitted fingerprint record gains two additional JSON fields:

- `cipher_hash_input`
- `ext_hash_input`

These fields contain the exact normalized comma-joined strings used before hashing, for example:

- `1301,1302,c02f`
- `0000,000d,0010,002b,0403,0804`

## Goals

- Preserve the current default JSON output schema for non-debug usage.
- Make Wireshark-vs-tool JA4 mismatch analysis directly observable from one command run.
- Keep the implementation local to the existing CLI, fingerprint, and output flow with minimal behavior change.

## Non-Goals

- Do not add a generic `--debug` umbrella flag.
- Do not emit raw TLS bytes or full parse trees.
- Do not change the JA4 calculation itself.

## Design

### CLI

Add `--debug-hash-inputs` as an optional boolean flag for:

- `ja4finger pcap`
- `ja4finger live`

The flag defaults to `false`.

### Fingerprint Result Shape

Extend the emitted result model so it can optionally carry:

- `cipher_hash_input`
- `ext_hash_input`

When debug mode is disabled, these fields are omitted from JSON output.

### Data Source

The values come from the exact normalized inputs already used by the JA4 implementation:

- `cipher_hash_input`: sorted non-GREASE cipher suite hex values joined by commas
- `ext_hash_input`: sorted non-GREASE extension hex values, then signature algorithm hex values appended under the current implementation rule, joined by commas

### Verification

Add tests that confirm:

- default output does not contain the debug fields
- debug mode includes both input strings
- the debug strings match the inputs used to produce the expected JA4 regression value

## Risks

- If the implementation exposes a string that is not exactly the pre-hash input, the feature becomes misleading.
- If debug fields are always emitted instead of omitted-by-default, existing consumers could break.
