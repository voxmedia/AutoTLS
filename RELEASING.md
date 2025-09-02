> This guide is for maintainers. Contributors do not need to follow these steps.

# Releasing AutoTLS

This document describes the release process for AutoTLS.
It's intended for maintainers only.

------------------------------------------------------------------------

## Branching

-   `main` is always stable and production-ready.
-   New work comes in via feature/fix branches and PRs.
-   Releases are staged on dedicated **release branches**
    (`release/x.y.z`).
-   **Contributors do not tag or version-bump** --- maintainers handle
    releases.

------------------------------------------------------------------------

## Versioning

We use [Semantic Versioning](https://semver.org/):
- **MAJOR** → incompatible API/behavior changes
- **MINOR** → new features, backwards-compatible
- **PATCH** → bug fixes or internal improvements

------------------------------------------------------------------------

## Release flow

1.  **Collect PRs** into the current release branch:

    -   Retarget PRs to `release/x.y.z` (Open the PR, Edit, and select the desired release branch from the base branch drop-down menu. Confirm the change by clicking "Change base.")

2.  **Stabilize the release branch**:

    -   Only accept fixes and docs updates.
    -   Confirm automated tests pass.
    -   Update docs/CHANGELOG.

### When the batch is ready to ship

3.  **Bump version** in `pyproject.toml`:

    ``` bash
    git add pyproject.toml
    git commit -m "Release: vX.Y.Z"
    git push origin release/x.y.z
    ```

4.  **Merge back and tag**:

    ``` bash
    git checkout main
    git pull origin main
    git merge --no-ff release/x.y.z
    git push origin main

    git tag vX.Y.Z
    git push origin vX.Y.Z
    ```

5.  **Create a GitHub Release** for the tag:

    -   Go to [Releases](/releases/new) → Draft a new release, select tag vx.y.z.
    -   Click Auto-generate release notes (edit if needed).
    -   Publish.

------------------------------------------------------------------------

## Clean up & prep next cycle

1.  **Create a new release branch** from `main`:

    ``` bash
    git checkout main
    git pull origin main
    git checkout -b release/x.y.z+1
    git push -u origin release/x.y.z+1
    ```

2.  **Delete the old release branch**:

    ``` bash
    git branch -d release/x.y.z
    git push origin --delete release/x.y.z
    ```

3.  **Open the next [milestone](/milestones)** (e.g., `vx.y.z+1`).

    - Assign PRs/issues to this milestone so it’s clear what’s targeted for the upcoming release.

4.  **Keep a draft changelog** or GitHub Release notes for upcoming changes.


