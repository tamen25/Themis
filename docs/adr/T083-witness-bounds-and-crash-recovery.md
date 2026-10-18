# T083: Bounded observation with no session resumption or cleanup dependency

Registration lasts at most 20 seconds; sampling lasts at most 12 seconds with at
most 100 sequential paired samples, at least 100 ms between starts. HTTP uses the
existing bounded no-proxy/no-redirect fixture transport. Journals have 128 records,
32 KiB per record and 2 MiB total limits. Every append is checked and synced;
short writes poison the writer. A session is claimed exclusively and cannot resume.

Actual process-death tests retain complete signed prefixes and torn tails without
inventing a terminal or samples. Inspection is read-only. Filesystem stalls may
outlast deadlines; the fixture's existing independent expiry and original runner
cleanup never depend on witness progress. Later reconciliation cannot rewrite the
historical result. There is no power-loss or filesystem-wide quota guarantee.
