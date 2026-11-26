# Vendored xterm.js

Served by `rbq term serve` from the binary itself; no CDN at runtime.

| File | Package | npm tarball SHA-256 |
| --- | --- | --- |
| `xterm.js`, `xterm.css` | `@xterm/xterm@5.5.0` (MIT, `LICENSE.xterm`) | `bd954fa721872170188cc5d7e83e88db3c83c9a18a4e8d24c2783d26491f59d2` |
| `addon-fit.js` | `@xterm/addon-fit@0.10.0` (MIT, `LICENSE.addon-fit`) | `917ac44972453d5eed52edc1e50260c76398ce48cf2290c2e60671102bba0b33` |

Update by `npm pack` of the exact versions, checking the tarball digests,
and copying `lib/xterm.js`, `css/xterm.css` and `lib/addon-fit.js` unchanged.
