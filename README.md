# DNSSVC.R4X

`DNSSVC.R4X` is an independent R4OS service implemented in Zig.

## Package

- Version: see `module.R4MF`
- Image target: `/R4OS/SERVICES/DNSSVC.R4X`
- Image scope: `slim`
- Canonical project manifest: `module.R4MF`

The manifest is the single source of truth for the artifact, imports, image
target, and package metadata.

## Build

On Windows:

    Build.bat

On Linux or macOS:

    ./Build.sh

The build starters resolve the current local R4OS dependency checkouts through
`Settings.R4S`. The URL and hash entries in `build.zig.zon` record the
last verified standalone dependency identities; workspace builds use the
mapped local checkouts.

## Documentation

Detailed German technical notes from the migration are preserved in
`DOCUMENTATION.de.txt`. Source-transfer provenance is recorded in
`PROVENANCE.txt`.

## License

Original R4OS material is licensed under Apache License 2.0. See `LICENSE`
and `NOTICE`. Any repository-specific external material is documented in
`THIRD_PARTY_NOTICES.md`.

## Family-aware provider path

The copied Query2 network contract is served by the original endpoint and
resource owners. The0.90.33 provider revision adds actual IPv6 transport and
explicit wildcard dualstack where qualified; current limits and lifetimes
are specified in Contract/API/Ipv6Transport.txt. Existing consumer imports
and old operations retain their original path.

DNS A/AAAA selection is independent of the server address family. An explicit
endpoint selects one server; otherwise the ordered local
`C:\R4OS\CONFIG\RESOLVERS.R4S` list shares one finite whole transaction budget.
Empty/missing configuration uses the existing IPv4 resolver, malformed input
is an error. Pure complete-answer wire decoding remains owned by NetDns.
