# Contributing to the OpenShift Control Plane Components/Repositories

This document serves as a guide for contributing to the OpenShift components/repositories
that the OpenShift Control Plane group is responsible for maintaining.

This document is explicitly for contributions to individual component repositories and not for high-level
feature proposals within OpenShift.

Feature proposals should follow the OpenShift Enhancement Proposal process outlined in https://github.com/openshift/enhancements/blob/master/dev-guide/feature-zero-to-hero.md#openshift-feature-development-zero-to-hero-guide.
If you are looking for a review on an OpenShift Enhancement Proposal that involves changes to components
maintained by the control plane group, please request a review in the [`#forum-ocp-apiserver`](https://redhat.enterprise.slack.com/archives/CB48XQ4KZ) Slack channel. Requests for review may be redirected to more appropriate and/or more focused channels for discussion.

This document contains the following sections:

- [Code conventions](#code-conventions) - A collection of guidelines, style suggestions, and tips for writing code.
- [Testing guidelines](#testing-guidelines) - Guidelines and expectations for testing of contributions.
- [Pull Request process/guidelines](#pull-request-process-and-guidelines) - Guidelines and expectations of pull requests containing contributions.
- [Review expectations](#review-expectations) - Guidelines and expectations for requesting reviews and interacting with reviewers.

## Code Conventions

We largely follow the [Kubernetes Code Conventions](https://github.com/kubernetes/community/blob/main/contributors/guide/coding-conventions.md#code-conventions).

Review both the Kubernetes Code Conventions and the ones specified here.
There will be some overlap. If any conventions are at odds with one another, prefer the conventions explicitly documented here.

### Bash

- Follow the [shell styleguide](https://google.github.io/styleguide/shellguide.html).
- Use [`shellcheck`](https://github.com/koalaman/shellcheck) to identify common mistakes or caveats.
- Ensure that all scripts run consistently across Linux and MacOS.

### Golang (Go)

- Review [Effective Go](https://go.dev/doc/effective_go).
- Review common [Go Code Review Comments](https://go.dev/wiki/CodeReviewComments).
- Review and avoid [Go Landmines](https://gist.github.com/lavalamp/4bd23295a9f32706a48f)
- Comment your code following the [Go comment conventions](https://go.dev/doc/comment).
  - Comments should be meaningful and add context and/or explain choices that cannot be expressed through clear code.
  - All exported types, functions, and methods must have descriptive comments.
  - All unexported types, functions, and methods should have descriptive comments.
- When adding command-line flags, use dashes/hyphens (`-`) and not underscores (`_`).
- Naming
  - Please consider package name when selecting an interface name, and avoid redundancy. For example, `storage.Interface` is better than `storage.StorageInterface`.
  - Do not use uppercase characters, underscores, or dashes in package names.
  - Please consider parent directory name when choosing a package name. For example, `pkg/controllers/autoscaler/foo.go` should say `package autoscaler` not `package autoscalercontroller`.
    - Unless there's a good reason, the package foo line should match the name of the directory in which the .go file exists.
    - Importers can use a different name if they need to disambiguate.
  - Locks should be called `lock` and should never be embedded (always `lock sync.Mutex`). When multiple locks are present, give each lock a distinct name following Go conventions: `stateLock`, `mapLock` etc.
- Context propagation
  - When a function accepts or has access to a `context.Context`, pass it through to downstream calls that accept one. Never discard a context or substitute `context.Background()`/`context.TODO()` when a context is already available.
- Error handling
  - Wrap errors with meaningful context before returning or logging them.
- When logging, follow the [Kubernetes Logging Conventions](https://github.com/kubernetes/community/blob/main/contributors/devel/sig-instrumentation/logging.md).
- When patching OpenShift-maintained forks of "upstream" repositories, patches should be as small as reasonably possible and should minimize touch points with code that is likely to change and impact the rebasing process.
- Dependencies must be vendored. When making changes to dependencies, ensure you've run `go mod tidy` and `go mod vendor`.

### General

Regardless of the programming language, make sure to take the following into consideration:

- Keep readability / maintainability in mind when writing code.
  - Clever code and abstractions are often harder to reason about after the fact. Keep clever code and abstractions to the minimum necessary to accomplish the end-goal.
- Do not reinvent the wheel. Where possible, use existing standard library or vendored library functionality. If you are adding a net-new dependency, stop and think if you _really_ need to add the new dependency to achieve your goals.
- When writing tests, focus on testing the functional behaviors your code exercises. Avoid writing tests that are testing that the standard library works as expected or is trivial. Do not write tests just for line coverage.

### Directory and File Conventions

- Avoid package sprawl. Find an appropriate subdirectory for new packages.
  - Libraries with no appropriate home belong in new package subdirectories of `pkg/util`.
- Avoid general utility packages. Packages called "util" are suspect. Instead, derive a name that describes your desired function. For example, the utility functions dealing with waiting for operations are in the `wait` package and include functionality like `Poll`. The full name is `wait.Poll`.
- All filenames should be lowercase.
- Go source files and directories use underscores, not dashes.
  - Package directories should generally avoid using separators as much as possible. When package names are multiple words, they usually should be in nested subdirectories.

## Testing Guidelines

These are high-level testing guidelines. Where individual component repositories may have
additional testing guidelines to follow when making contributions.

- All changes must include unit test additions/changes.
  - Exceptions are at reviewer/approver discretion.
- Table-driven unit tests are preferred for testing multiple scenarios/inputs. For an example, see https://github.com/openshift/cluster-authentication-operator/blob/a493799952e9b6838021ccc7d15d3d37d7ad3508/pkg/controllers/externaloidc/externaloidc_controller_test.go#L108 .
- Unit tests must pass on all platforms (at the very least, Linux + MacOS).
- Significant features should come with integration and/or end-to-end (e2e) tests where appropriate.
  - End-to-end tests _may_ be scoped as a separate work item when the end-to-end tests for the component must be added to the openshift/origin repository instead of the component repository. Adding e2e tests to the component repository is preferred where possible. It is up to reviewer/approver discretion whether a contribution can be merged without end-to-end tests being implemented.
- Do not expect an asynchronous thing to happen immediately. Do not wait for one second and expect a pod to be running. Wait and retry instead.

If necessary, manual integration testing can be done by creating a cluster using the [`Cluster Bot` Slack App](https://redhat.enterprise.slack.com/archives/D03KX7M1CRJ).
Once you have a cluster created, you can follow some of the instructions in https://github.com/openshift/enhancements/blob/master/dev-guide/operators.md for guidance on how to
build component images and modify cluster-operators to deploy those images.

Most component repos have existing tooling to run unit tests. Check for Makefiles and shell scripts that might run the unit tests. If none exist, you should be able to use standard testing tooling like `go test ./...` to run all tests for the project. https://pkg.go.dev/cmd/go/internal/test is a good reference for how the `go test` command works.

## Pull Request Process and Guidelines

This section assumes that you have a functional understanding of `git` and how to create a pull request on GitHub.

If you do not, start with [GitHub's "Getting Started" guide](https://docs.github.com/en/get-started/start-your-journey).

### Prerequisites

Before you commit any changes or create any pull requests, you must adhere to OpenShift contribution policies.
Currently, that means enabling commit signature verification.

See https://docs.google.com/document/d/1184EPSGunUkcSQYUK8T4a6iyawwi6f2zxdbB2jtG9nQ/edit?usp=sharing for more details on
how to adhere to the commit signature verification policy of OpenShift.

### Creating a Pull Request

When creating a pull request, include the following:

- A brief, but descriptive, title.
  - All pull requests _should_ link to a Jira ticket associated with the work. There is automation that performs this linking when prefixing the title with the Jira ticket identifier like: `CNTRLPLANE-XXXX: my pull request title`. For pull requests that have no Jira ticket associated with it, you can prefix it with `NO-JIRA:` to signal that there is not a Jira ticket associated with it.
- A useful description of the changes being made and why they are important. Include links to supporting documents and any additional context that reviewers may need.

### CI / CD

For CI/CD, OpenShift uses Prow to run various checks. This can include unit tests, e2e tests, linters, etc.

The jobs configured for each repository are in https://github.com/openshift/release/tree/main/ci-operator/config/openshift . If you find yourself needing to add additional jobs, review the documentation at https://docs.ci.openshift.org/how-tos/contributing-openshift-release/ .

There are often a mixture of required and optional checks as well as merge criteria that must be met before a pull request can merge.
When any of these checks fail, the GitHub Prow bot will leave a comment on the PR with links to the run of that check that failed.

As the PR author, it is your responsibility to evaluate the failed checks and determine if there are any changes necessary to pass the checks.
If you suspect that the check failure was a flake, you can trigger retests by commenting `/retest` (or `/retest-required` for retesting only the required checks) on the PR.

### Verifying your changes / Creating an OpenShift cluster from a PR

As part of merging a PR, there is a requirement to verify that the changes you've made are working as expected using the `/verified` comment command.

While there are a lot of scenarios where the existing CI/CD checks may be sufficient to verify your changes are working (and can be denoted by commenting `/verified by ci`),
there may be scenarios where manual verification is required.

You can use the `Cluster Bot` Slack App to create a cluster from a PR by sending it a message in the format of `launch ${OCP_VERSION},${PR_LINK} ${PLATFORM},${VARIANT}`.
As an example, `launch 4.23,https://github.com/openshift/oauth-proxy/pull/373 aws,techpreview` would launch an OpenShift 4.23 cluster with the changes made in openshift/oauth-proxy#373 running on AWS with the TechPreviewNoUpgrade feature-set enabled.
For more information on what `Cluster Bot` can do, you can send it a message saying `help` and it will respond with additional documentation on how it can be used.

Once you've verified your changes work as expected, you can mark the PR as verified by commenting `/verified by @{your_github_handle}` on the PR.

### Additional Resources

For more information regarding more general OpenShift pull request processes, the following resources are helpful:

- https://docs.ci.openshift.org/architecture/jira
- https://docs.ci.openshift.org/
  https://steps.ci.openshift.org/

## Review Expectations

### Requesting a review

If you are not a member of the OpenShift control plane team and you need a review on a PR, post it in the [#forum-ocp-apiserver](https://redhat.enterprise.slack.com/archives/CB48XQ4KZ) Slack channel or
reach out to folks outlined in the OWNERS file directly.

If you are a member of the OpenShift control plane team, reviews should come from your feature team. In the event your feature team does not have someone that can approve
a PR, post it in the [#control-plane](https://redhat.enterprise.slack.com/archives/CC3CZCQHM) Slack channel.

OpenShift uses AI code review tools as part of the code review process.
Before requesting a review, address all feedback from the code review agent(s).
It is up to your discretion as the contributor how you would like to address that feedback.
Responding with an explanation as to why you are not going to take action on a comment made
by the agent is an acceptable way to "address" its feedback.

### Interacting with reviewers

When interacting with reviewers/approvers:

- Be professional.
- Be respectful of differing opinions, viewpoints, and experiences.
- Gracefully give and receive constructive feedback.
- Focus on what is best for the product/organization, not just us as individuals.

A special note on the usage of AI - to respect the time of those that are reviewing your contribution, please do not use AI to respond to review comments.

# Specific Guidelines for `oauth-proxy`

## Pre-Submit Checks

Before pushing your changes, run:

```sh
make build
make test-unit
```

The unit target runs the repository's non-e2e Go packages with the race detector. Focused tests can be run with standard Go tooling, for example:

```sh
go test ./providers/openshift/...
go test . -run TestName
```

## Dependency Management

This repository vendors all Go dependencies. After adding, removing, or updating a dependency:

```sh
go mod tidy
go mod vendor
make test-unit
```

Commit `go.mod`, `go.sum`, and the resulting `vendor/` changes together. Do not edit files under `vendor/` directly.

## Configuration Changes

When adding or changing configuration, keep flag registration in `main.go` or the OpenShift provider's `Bind` methods aligned with the `Options` fields, TOML keys, supported environment tags, defaults, validation, examples, tests, and user documentation.

Changes to public flags, defaults, endpoints, cookie/session formats, forwarded identity headers, OAuth scopes, or authentication and authorization caches require particular compatibility and security review.

## E2E Test Suite

Cluster-dependent tests are under `test/e2e/`:

| Suite | Makefile target | Timeout | Notes |
| --- | --- | --- | --- |
| `test/e2e/` | `make test-e2e` | 3h | Serial (`-p 1`); requires a configured OpenShift cluster |

The target disables test caching and runs the package serially because tests share cluster resources. Do not parallelize it without accounting for those resources.
