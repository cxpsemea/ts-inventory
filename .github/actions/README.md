# Ready to use github actions

Github actions usable to automate your workflows.

## Usable to lint and version (tag) 

#### github-check-code
To check the source code using Ruff linter.

Refer to [Ruff Linter](https://docs.astral.sh/ruff)

#### github-release
To create a new version and release tag based on SemVer conventional commits specifications.

Refer to [SemVer](https://semver.org)

## Usable to build and publish binaries and/or docker images

#### github-build-alpine
Builds Alpine Linux executable binaries and publishes it as a .tar.gz.

#### github-build-rocky
Builds Rocky Linux executable binaries and publishes it as a .tar.gz.

#### github-build-ubuntu
Builds Ubuntu Linux executable binaries and publishes it as a .tar.gz.

#### github-build-windows
Builds Windows executable binaries and publishes it as a .zip.

#### github-build-macos
Builds MacOS executable binaries and publishes it as a .tar.gz.

#### github-build-docker
Builds Docker image with executable binaries and publishes it as a .tar.

The docker image can be manually added to a docker instance.

#### github-publish-docker
Builds Docker image with executable binaries and publishes (uploads) it at github image repository.

Refer to [ghcr.io](https://ghcr.io)
