# T068: Verify physical bytes and independently retained WAL

Status: Implemented for disposable local T3.2; independent review required.

Use pinned PostgreSQL 18.6 tar/fetch base backups, bounded protected host
publication and full plain-directory pg_verifybackup including WAL parsing.
The archive has its own owned volume, fixed bounded exclusive publication and
post-failure readability checks. Require contiguous checksummed segment coverage,
observed named target in archived WAL and a final signed preparation seal before
fault authority. An archive counter or successful backup tool is insufficient.
No filesystem-wide local-driver quota or power-loss durability is claimed.
