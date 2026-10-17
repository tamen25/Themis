# T063: Separate persistent logical-recovery storage

Status: Accepted for T3.1's disposable local synthetic scope.

T3.0's tmpfs and controlled stop remain unchanged. A new durable version creates
two distinct default local-driver persistent volumes, bound by random name,
creation time, labels, exact original mounts and Docker engine. Measured database,
volume and free-space guards bound a fixed workload; an 8 MiB per-file limit is
hard. There is no claimed filesystem-wide volume quota on the tested engine.

A private host artifact is independent of both container/volume lifecycles.
Publish only complete synced custom-1.16.0 bytes validated with pinned tools,
exclusive hard-link creation, signed content/file identity metadata, and a final
preparation seal. Reopening rejects substituted identical-byte files as well as
truncation and corruption. File and supported directory synchronization do not
prove power-loss or off-site durability. Partial installation with no final
sealed inventory requires review of acknowledged installation records; resource
identities are never guessed. Physical backup and WAL/PITR remain separate future
experiments.
