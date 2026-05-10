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

> **⚠ License must be verified before public redistribution.**

The MetaCubeX/meta-rules-dat repository aggregates data from multiple upstream
sources (MaxMind GeoLite2, v2ray/domain-list-community, etc.), each with its own
license terms. The precise redistribution terms of the aggregated binary output
**have not been independently confirmed** for this repository.

- MaxMind GeoLite2 data is subject to the [MaxMind CC BY-SA 4.0 license](https://dev.maxmind.com/geoip/geolite-free-geolocation-data).
- v2ray/domain-list-community is MIT-licensed.

If you redistribute these files, you are responsible for complying with all
upstream licenses. Consult the
[MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)
repository for current license details.

## Update Process

1. Download fresh copies from the URLs listed above (or build from source via
   the MetaCubeX toolchain).
2. Replace `geoip.dat` and `geosite.dat` in this directory.
3. Commit the updated binaries. The `.gitattributes` file at the repository root
   marks `*.dat` as `binary` to suppress text-diff noise.

## Recommendation

For long-term maintenance, consider migrating these assets out of the Git
repository and into:
- GitHub Release assets downloaded at build time, or
- Git LFS, or
- A first-run download script triggered by `ensureGeoRulesAssets()`.

This reduces repository bloat (~23 MB of binary data) and simplifies version
tracking.
