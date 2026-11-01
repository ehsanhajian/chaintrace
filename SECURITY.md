# Security

ChainTrace reads process metadata for a node you already run. `status` and `check` use the process table. `watch` attaches a read-only bpftrace probe to one pid. The probe needs root. Run it only on a host you administer.

ChainTrace does not read file contents, store keys, open a connection, or stop the process. A password-style command argument is printed as `[redacted]`. Paths and destination addresses are printed, because that is the observation.

Report a vulnerability through [GitHub private vulnerability reporting](https://github.com/ehsanhajian/chaintrace/security/advisories/new). Do not paste a key, a JWT, or a password into the report.
