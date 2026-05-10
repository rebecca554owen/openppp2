# GeoIP / GeoSite Rule Assets

## Purpose

Pre-bundled binary GeoIP and GeoSite databases for the Android VPN service.
`PppVpnService.ensureGeoRulesAssets()` extracts these files on first launch so
that the native engine can parse `./rules/GeoIP.dat` and `./rules/GeoSite.dat`
without a network download, avoiding a ~60-second blocking hang on cold start.

## Files

| File | Approx. Size | Description |
|------|-------------|-------------|
| `geoip.dat`  | ~19 MB | IP-to-country CIDR database (protobuf `GeoIPList`) |
| `geosite.dat` | ~4 MB  | Domain-to-category rule database (protobuf `GeoSiteList`) |

## Source

These `.dat` files are in **v2ray/xray binary geo format** (protobuf-encoded
`GeoIPList` / `GeoSiteList`).

The bundled copies originate from the **MetaCubeX/meta-rules-dat** release
channel, which is the same upstream used by the project's configurable download
URLs:

```
https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat
https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat
```

## License / Redistribution

> **⚠ HARD GATE: License must be confirmed BEFORE any public release or redistribution.**

The MetaCubeX/meta-rules-dat repository aggregates data from multiple upstream
sources (MaxMind GeoLite2, v2ray/domain-list-community, etc.), each with its own
license terms. The precise redistribution terms of the aggregated binary output
**have not been independently confirmed** for this repository.

- MaxMind GeoLite2 data is subject to the [MaxMind CC BY-SA 4.0 license](https://dev.maxmind.com/geoip/geolite-free-geolocation-data).
  Requires attribution and share-alike compliance.
- v2ray/domain-list-community is MIT-licensed.
- The aggregated `.dat` binary's redistribution compatibility with these
  upstream licenses has **not** been independently verified.

**You MUST NOT include these `.dat` files in a public Release artifact until
the redistribution license has been explicitly confirmed.** If confirmation is
not possible before the planned release date, migrate to one of the alternatives
listed in the Migration section below.

## Update Process

1. Download fresh copies from the URLs listed above (or build from source via
   the MetaCubeX toolchain).
2. Replace `geoip.dat` and `geosite.dat` in this directory.
3. Commit the updated binaries with a message that includes the upstream
   version/date (e.g., `chore(android): update geo-rules from MetaCubeX 2026-05-11`).
   The `.gitattributes` file at the repository root marks `*.dat` as `binary`
   to suppress text-diff noise.

## Migration (Required Before Public Release)

For long-term maintenance and license compliance, these assets MUST be migrated
out of the Git repository before any public release. Choose one of:

- **GitHub Release assets**: download at build time via CI script.
- **Git LFS**: track `*.dat` via LFS to reduce repository clone size.
- **First-run download**: triggered by `ensureGeoRulesAssets()` on first launch,
  with a bundled CDN fallback.

This eliminates ~23 MB of binary data from the repository and ensures that
license compliance can be managed independently of the Git history.
