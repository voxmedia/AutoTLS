# Contributing to AutoTLS

:+1: Thanks so much for your interest in contributing, and thank you in advance for your time!

The following is a set of guidelines for contributing to AutoTLS, which is hosted at [https://github.com/voxmedia/AutoTLS](https://github.com/voxmedia/AutoTLS) on GitHub.

#### Table Of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
    - [Report Bugs](#report-bugs)
    - [Suggest Features](#suggest-features)
    - [Write Documentation](#write-documentation)
- [Your First Code Contribution](#your-first-code-contribution)
    - [Pull Requests](#pull-requests)


## Code of Conduct

This project and everyone participating in it is governed by the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to [cpe-team@voxmedia.com](mailto:cpe-team@voxmedia.com?subject=Code%20of%20Conduct).


## How Can I Contribute?

### Report Bugs

Before creating a bug report, please check the [Issues](https://github.com/voxmedia/AutoTLS/issues?q=state%3Aopen%20label%3A"bug") page first to see if the bug you're experiencing has already been reported. When you are creating a bug report, please include as many details as possible. Fill out [the required template](https://github.com/voxmedia/AutoTLS/blob/main/.github/ISSUE_TEMPLATE/bug_report.md), the information it asks for helps us resolve issues faster.

> **Note:** If you find a **Closed** issue that seems like it is the same thing that you're experiencing, open a new issue and include a link to the original issue in the body of your new one.

* **Use a clear and descriptive title** for the issue to identify the problem.
* **Describe the exact steps which reproduce the problem** in as many details as possible. For example, start by explaining how you started the application, e.g. what command you used in the terminal.
* **Describe the behavior you observed after following the steps** and point out what exactly is the problem with that behavior.
* **Explain which behavior you expected to see instead and why.**
* **Include screenshots and/or animated GIFs** which show you following the described steps and clearly demonstrate the problem. You can use [this tool](https://www.cockos.com/licecap/) to record GIFs on macOS and Windows, and [this tool](https://github.com/colinkeenan/silentcast) or [this tool](https://github.com/GNOME/byzanz) on Linux.
* **If you're reporting a crash**, include a stack trace from the application log. Include the stack trace in the issue in a [code block](https://help.github.com/articles/markdown-basics/#multiple-lines), as a [file attachment](https://help.github.com/articles/file-attachments-on-issues-and-pull-requests/), or put it in a [gist](https://gist.github.com/) and include the link to that gist.
* **If the problem wasn't triggered by a specific action**, describe what you were doing before the problem happened and share more information using the guidelines below.

Provide more context by answering these questions:

* **Can you reliably reproduce the issue?** If not, provide details about how often the problem happens and under which conditions it normally happens.
* **Which version of the application are you using?** 
* **What's the name and version of the OS you're using**?
* **Are you running the application in a virtual environment?** If so, are the correct environment variables set? You can get that list by running `printenv` (or `set` on Windows).
> **WARNING**: Please do not paste your environment variables with their values into the body of the issue. This is for your own protection - any issue filed that includes a user's specific env var values will be deleted.

#### Windows Support

If your bug is happening in a Windows operating system, our ability to help will be limited. None of the authors of this application work in Windows. That said, if you are a developer working in Windows and want to run this application, we would love to talk to you about your experience! Contact us at: [cpe-team@voxmedia.com](mailto:cpe-team@voxmedia.com?subject=TLS%20Tool%20Windows).

### Suggest Features

Before submitting a feature request, please check the [Issues](https://github.com/voxmedia/AutoTLS/issues?q=state%3Aopen%20label%3A"enhancement") page for existing feature requests. When you are creating a feature request, please include as many details as possible. Fill in [the feature request template](.github/ISSUE_TEMPLATE/feature_request.md), including the steps that you imagine you would take if the feature you're requesting existed.

* **Use a clear and descriptive title** for the issue to identify the suggestion.
* **Is your feature request related to a problem you've observed**?  Please provide a concise description of what the problem is.
* **Provide a step-by-step description of the suggested feature** in as many details as possible.
* **Provide specific examples to demonstrate the feature's usage**. Feel free to include copy/pasteable code snippets.
* **Explain why this feature would be useful**.
* **Are you planning to provide a pull request to implement this feature?** If so, please note that in the ticket.

### Write Documentation

We can always use more documentation! If there's something about the application that you don't understand, there's no better way to learn than to dig into the feature or behavior and document it yourself!


## Your First Code Contribution

Unsure where to begin? Start by looking through the list of [open issues](https://github.com/voxmedia/AutoTLS/issues?q=state%3Aopen) for bugs and reqested features. If you're looking for something a little more advanced, feel free to check out our [road map](ROADMAP.md), which acts as a sort of wish list for new features. (If you plan to work on an item from the road map, please open a [feature request](#suggest-features) first - maintainers may want to discuss the planned feature with you.)

### Local development

* Read this guide
* Fork this repository, then clone your fork locally
* Cut a new branch. Your branch name should reference the issue number you are addressing and its type, e.g.
    * `autotls-bug-report-52`
    * `autotls-feature-request-123`
* Write your code. For instructions on how to run the app locally, see the [Quickstart section in the README](README.md#quickstart).
* Write some tests to cover the code you've written. Information about linting and running tests locally is covered in the [testing doc](TESTING.md).
* Verify that all tests are passing by running the [unit test workflow](https://github.com/voxmedia/AutoTLS/actions/workflows/pytest.yaml) against your branch.
* Document! For new features, and if applicable for bug fixes, please update any related docstrings, then generate and review the mkdocs documentation:
```
mkdocs build -v       # outputs static site into ./documentation/
mkdocs serve          # live preview at http://127.0.0.1:8000
```
* Once you're satisfied with your changes, commit to your branch and push to GitHub.

### Pull Request Guidelines

When opening a PR:

1. **Target the latest release branch**  
   - Open a pull request comparing your branch to this repository's latest release branch.
   - Branches are named `release/x.y.z`.  
   - You can find the current one in the branch dropdown when creating your PR.

2. **Assign a milestone**  
   - In the PR sidebar, under **Milestone**, choose the current milestone (e.g. `v0.3.0`).  
   - This helps maintainers track what’s going into the next release.  

3. **Keep PRs focused**  
   - One feature or fix per PR is best.  
   - Make sure tests pass and docs are updated if behavior/config changed.
   - For bug fixes and features, include a link to the relevant [issue](https://github.com/voxmedia/AutoTLS/issues?q=state%3Aopen)

> Tip: Milestones and labels live in the PR sidebar (right-hand column in the GitHub UI).

[This article from Geeks for Geeks](https://www.geeksforgeeks.org/git/making-first-open-source-pull-request/) is a great reference on the steps involved in opening a pull request against a repository.

