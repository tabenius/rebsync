# Probe evidence

The runner writes `object-store.json` and `opendal.json` here only after a probe
successfully completes. A build in progress is not a passing result. Each report
records the probe/manifest/lockfile hash and compiler used.

Run `python3 evaluations/storage/run.py --resume` from the repository root to
reuse matching results and execute unfinished or changed probes. Observed
semantic limitations are findings, not provider certification.
