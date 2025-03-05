# Setup your development environment

1. Ensure you have a feature branch created to work on.
2. Run "**setupdev**" script (bat for windows, sh for posix), to set all up.
3. Optionally, run "**setupsubmodule**" script (bat for windows, sh for posix), to add the shared submodule if you need it.

#### The setup process will enforce the following automations:
- Install Python dev and build requirements.
- Prepare basic configurations for vscode (the .vscode folder).
- Create a pre-commit hook for source code analysis with Ruff linter.
- Create a commit-msg hook for enforcing commit conventions with CommitLint linter.

#### Commit message rules

Commit messages **MUST** comply with SemVer and conventional commits specifications, using Angular convention.
Accepted commits are:
- chore: *major changes*.
- feat: *new features*.
- fix: *fixes*.
- perf: *performance related*.
- docs: *documentation related*.
- build: *build process related*.
- ci: *automation/pipeline related*.
- refactor: *refactors not changing functionality*.
- style: *presentation/ui related*.
- test: *testing and qa related*.

#### References
- [Ruff Linter](https://docs.astral.sh/ruff)
- [CommitLint](https://pypi.org/project/commitlint)
- [Semantic Release](https://python-semantic-release.readthedocs.io)
- [Conventional commits](https://www.conventionalcommits.org)
- [SemVer](https://semver.org)
