# GeoIP / GeoSite Rule Assets

## Purpose

Pre-bundled binary GeoIP and GeoSite databases for the Android VPN service.
`PppVpnService.ensureGeoRulesAssets()` extracts these files on first launch so
that the native engine can parse `./rules/geoip.dat` and `./rules/geosite.dat`
without a network download, avoiding a ~60-second blocking hang on cold start.

## File Inventory

| File | Approx. Size | Format | Description |
|------|-------------|--------|-------------|
| `geoip.dat`  | ~19 MB | Protobuf `GeoIPList` | IP-to-country CIDR database |
| `geosite.dat` | ~4 MB  | Protobuf `GeoSiteList` | Domain-to-category rule database |

> **Tip:** After each refresh, record `sha256sum geoip.dat geosite.dat` in the
> commit message or a companion log so that reviewers can verify provenance
> without bloating the repository with checksum files.

## Upstream Source

| Field | Value |
|-------|-------|
| **Repository** | [`MetaCubeX/meta-rules-dat`](https://github.com/MetaCubeX/meta-rules-dat) |
| **Artifact names** | `geoip.dat`, `geosite.dat` |
| **CDN mirror** | `https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/` |
| **Bundled version date** | `TODO: record on next refresh` |
| **Bundled version commit / tag** | `TODO: record on next refresh` |
| **Last reviewed** | `TODO: record on next refresh` |

The upstream repository aggregates data from multiple sources, primarily:

- **MaxMind GeoLite2** — IP geolocation data, licensed under
  [CC BY-SA 4.0](https://dev.maxmind.com/geoip/geolite-free-geolocation-data)
  (requires attribution and share-alike compliance).
- **v2ray/domain-list-community** — domain categorization rules,
  [MIT-licensed](https://github.com/v2fly/domain-list-community).

## License & Redistribution Notes

Per maintainer guidance, these `.dat` rule files **may be included in release
artifacts** — this is a non-blocking, best-effort governance area.

Recommended best practices (not blockers):

1. **Record upstream attribution** — acknowledge MaxMind GeoLite2 (CC BY-SA 4.0)
   and v2ray/domain-list-community (MIT) in release notes or a NOTICE file.
2. **Track provenance** — on each refresh, log the upstream commit/tag and
   download date alongside the sha256 hash (see Update Procedure below).
3. **Re-confirm upstream license periodically** — if the MetaCubeX aggregation
   terms change, update this section accordingly.

> This section is a **governance record**, not a release gate. If upstream
> license questions arise, they can be resolved post-merge without blocking the
> release pipeline.

## Update Procedure

When refreshing the bundled rule files:

1. **Download** fresh copies:
   ```
   curl -LO https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat
   curl -LO https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat
   ```
2. **Verify** file integrity (optional but recommended):
   ```
   sha256sum geoip.dat geosite.dat
   ```
3. **Replace** the files in this directory (`android/android/app/src/main/assets/rules/`).
4. **Update** the "Upstream Source" table above with the actual refresh date
   and commit/tag (replace the `TODO` entries).
5. **Commit** with a descriptive message, e.g.:
   ```
   chore(android): refresh geo-rules from MetaCubeX meta-rules-dat

   Source: MetaCubeX/meta-rules-dat@release
   Downloaded: 2026-05-11
   geoip.dat sha256: <hash>
   geosite.dat sha256: <hash>
   ```

The `.gitattributes` file at the repository root marks `*.dat` as `binary`
to suppress text-diff noise in `git log`.

## Future Optimization (Optional, Non-Blocking)

To reduce repository clone size, the `.dat` files could eventually be moved out
of Git into one of these distribution channels:

- **GitHub Release assets** — downloaded at build time via CI script.
- **Git LFS** — track `*.dat` via LFS.
- **First-run download** — triggered by `ensureGeoRulesAssets()` on first launch,
  with a bundled CDN fallback.

This would eliminate ~23 MB of binary data from the repository history.
This is an optional optimization and **not** a release prerequisite.
