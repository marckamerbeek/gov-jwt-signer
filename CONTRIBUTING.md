<!-- SPDX-License-Identifier: EUPL-1.2 -->

# Contributing to gov-jwt-signer

Thanks for your interest in improving this library. It is a small, security-focused
Go module, so a few of the guidelines below are stricter than in a typical project.
Please read them before opening a pull request.

## Design principles

Two constraints shape almost every decision in this codebase. Please respect them:

- **Minimal supply chain.** The only external dependency is
  `github.com/golang-jwt/jwt/v5`. JWK, JWKS, and the RFC 7638 thumbprint are
  implemented against the Go standard library. Do not add new dependencies without
  strong justification — expect to explain the trade-off in your pull request.
- **No organisation-specific variants in the library.** The three built-in token
  types (eIDAS, DigiD, eHerkenning) are domain standards. A one-off, organisation-
  specific token belongs in the calling application via `token.Service.IssueCustom`,
  not as a new built-in `Issue*` method.

## Getting started

Requires **Go 1.26** or newer (matching CI).

```sh
git clone https://github.com/marckamerbeek/gov-jwt-signer.git
cd gov-jwt-signer
make all        # build + vet + test
```

## Development workflow

1. Create a feature branch off `master`.
2. Make your change, with tests.
3. Run the full local suite before pushing:

   ```sh
   make build     # go build ./...
   make vet       # go vet ./...
   make test      # go test -race -cover ./...
   make lint      # golangci-lint run (skips if not installed)
   make vuln      # govulncheck ./... (skips if not installed)
   make tidy      # go mod tidy
   ```

4. Open a pull request against `master`.

CI runs vet, build, `go test -race`, and golangci-lint on Go 1.26. A green local
`make all` is the baseline; `make lint` and `make vuln` are strongly encouraged, as
CI enforces the linter.

## Coding conventions

- **Every `.go` file starts with `// SPDX-License-Identifier: EUPL-1.2`.**
- Code is formatted with `gofmt`; imports with `goimports` using the local prefix
  `github.com/marckamerbeek/gov-jwt-signer`.
- **Mixed language is intentional.** Comments and documentation are English;
  user-facing **error message strings, sentinel errors, and domain terms remain
  Dutch** (e.g. `"jwtsigner: WithIssuer is verplicht"`, `Betrouwbaarheidsniveau`).
  Do not "fix" the Dutch strings or translate test data unless that is the explicit
  point of your change.
- Errors are sentinel values matched with `errors.Is`; wrap them with `%w`.
- Keep the domain models (`pkg/claims`) free of any dependency on the JOSE
  implementation. `pkg/claims` imports nothing internal.

## Tests

- New behaviour needs test coverage. Run tests with the race detector:
  `make test` (i.e. `go test -race -cover ./...`).
- Run a single test with, for example,
  `go test -race -run TestName ./pkg/token/`.
- The `examples/` programs double as smoke tests; `go run ./examples/basic` should
  issue every variant, print the JWKS, and verify a token.

## Commit messages and pull requests

- Write focused commits with a clear subject line describing *what* changed and,
  where it isn't obvious, *why*.
- Keep unrelated changes in separate pull requests.
- In the pull request description, note any change to the public API or the token
  wire format, and call out anything touching key handling or algorithm selection.

## Security

Please **do not** open public issues for security vulnerabilities. Follow the
process described in [SECURITY.md](SECURITY.md) instead.

## License

This project is licensed under the **EUPL-1.2**. By contributing, you agree that
your contributions are licensed under the same terms, and you must keep the
`SPDX-License-Identifier: EUPL-1.2` header on every source file.
