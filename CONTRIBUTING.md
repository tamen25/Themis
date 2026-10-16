# Contributing

The development scope includes the T1.2 local foundation and T2.0 dry-run
Kubernetes projection. Read [the Kubernetes scope and real API tests](docs/kubernetes.md)
before changing the controller. Start with the
[README](README.md), [contract rules](docs/contracts.md) and
[ADRs](docs/adr/README.md). Discuss changes to the contract format or verdict
semantics in an issue before submitting a large patch.

Use idiomatic Go and explicit errors. Keep domain logic independent of CLI I/O.
Introduce a dependency only when it earns its maintenance cost. Prefer small
packages with an implemented responsibility over speculative abstractions.

Add behavioral tests with code changes. Cover invalid input and false-PASS risks,
not just successful examples. Unknown or unsupported input must fail visibly.
Never turn missing evidence, execution errors or skipped checks into PASS.
Optional checks must remain visible without affecting required-check aggregation.

Before submitting:

```sh
go fmt ./...
go vet ./...
go test ./...
go test -race ./...
go mod verify
go build -trimpath -o bin/ ./cmd/themis
```

Run the parser/verdict fuzz commands and vulnerability audit in the README when
changing those boundaries. Report checks that could not run and why. CI covers
all supported desktop platforms, with race and fuzz checks on Linux.

Changes to serialized artifacts require fixture review and a compatibility
decision; a changed golden file alone is not evidence of correctness. Contract
assertions are an unordered set keyed by ID; phases are an ordered sequence.
Record significant architectural changes under `docs/adr/` and document actual
behavior in the README.

Before starting T1 or implementing fault injection, complete T0 and provide a
review handoff containing the full Git patch (including untracked source files),
the relevant ADRs, exact validation commands and their results, and known gaps or
deviations. Wait for maintainer review of that handoff before building fault
execution on the foundation. A green test suite alone does not satisfy this
architecture review checkpoint.

The implementation guide is local planning material and must never be committed
or deleted. Keep its actual path in `.git/info/exclude` in each checkout; verify
with `git check-ignore -v -- <path>`. Do not broadly ignore Markdown or docs.

Use focused commits and PR descriptions explaining the behavior change,
validation and limitations. Do not include credentials, private contract data or
generated binaries. Contributions are provided under the repository's
[Apache-2.0 license](LICENSE).
