# Recon Engine Interface

Required invocation:

```text
recon-engine --target 127.0.0.1 --scope lab-runtime/scope.csv --output run/ --rate 25
```

Required output:

```text
run/
  run.json                 # versions, start/end UTC, arguments, exit status
  raw/<tool>/              # unedited tool output
  normalized/assets.jsonl  # one record per observed asset/service
  report.html
  errors.jsonl
```

Each normalized record must include `observed_at`, `target`, `port`, `protocol`,
`service`, `source_tool`, `source_file`, `confidence`, and `notes`. Vhost records
also include status, length, title, redirect, and baseline-difference fields.

Minimum tests: missing tool, timeout, malformed output, wildcard vhost,
duplicate service, scope rejection, interrupted run, and empty result.

The engine must enforce destination and port scope before opening a socket. The
target request ledger is independent corroboration for requests that reach the
two authorized services, but the candidate engine remains responsible for
proving that the `OUT` endpoint and all non-loopback destinations were rejected
before network activity.
