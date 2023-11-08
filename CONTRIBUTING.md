# Contributing to OpenPubkey

Welcome to OpenPubkey! We are so excited you are here. Thank you for your interest in contributing your time and expertise to the project. The following document details contribution guidelines.

# Getting Started

Whether you're addressing an open issue (or filing a new one), fixing a typo in our documentation, adding to core capabilities of the project, or introducing a new use case, anyone from the community is welcome here at OpenPubkey.

## Pull Request (PR) Process

OpenPubkey is managed from the `main` branch. To ensure your contribution is reviewed, all pull requests must be made against the `main` branch.

PRs must include a brief summary of what the change is, any issues associated with the change, and any fixes the change addresses. Please include the relevant link(s) for any fixed issues. 

Pull requests do not have to pass all automated checks before being opened, but all checks must pass before merging. This can be useful if you need help figuring out why a required check is failing.

Our automated PR checks verify that:
 1. All unit tests pass, which can be done locally by running `go test ./...`.
 2. The code has been formatted correctly, according to `go fmt`.
 3. There are no obvious errors, according to `go vet`.

## Testing OpenPubkey Locally

To build OpenPubkey, ensure you have Go version `>= 1.20` installed. To verify which version you have installed, try `go version`.

To run the [Google example](https://github.com/openpubkey/openpubkey/tree/main/examples/google):
 1. Navigate to the `examples/google/` directory. 
 2. Execute `go build`
 3. Execute `google login` to generate a valid PK token using Google as your OIDC provider.
 4. Execute `google sign` to use the PK token generated in (3) to sign a verifiable message.

# Current Committers

The Committers of OpenPubkey are:
1. Ethan Heilman (@EthanHeilman)
2. Jonny Stoten (@jonnystoten)
3. Lucie Mugnier (@lgmugnier)

# Contributing Roles

Contributors include anyone in the technical community who contributes code, documentation, or other technical artifacts to the OpenPubkey project.

Committers are Contributors who have earned the ability to modify (“commit”) source code, documentation or other technical artifacts in a project’s repository. Note that Committers are still required to submit pull requests.

A Contributor may become a Committer by a majority approval of the existing Committers. A Committer may be removed by a majority approval of the other existing Committers.

# Copyright

By contributing to this repository, you agree to license your work under the Apache License 2.0. Any work contributed where you are not the original author must display a license header with the original author(s) and source.