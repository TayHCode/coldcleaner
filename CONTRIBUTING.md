# Contributing

Bug reports and pull requests are welcome. Open an issue on this repository using the bug report template. Remove hostnames, usernames, personal paths and credentials from any report or log you paste.

For a pull request:

1. Keep the change small and use Python's standard library only.
2. Add or update a test for the behavior you changed.
3. Run `python3 -m unittest discover -s tests -v` with tar and zstd installed. Tests must use temporary data, local bare Git remotes and fake hosts, never real machines, archive storage or GitHub.

Report security problems privately as described in `SECURITY.md`, not in a public issue.

By submitting a contribution you agree to license it under the MIT License in `LICENSE`.
