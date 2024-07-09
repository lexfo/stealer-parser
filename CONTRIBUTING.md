# Contributing guidelines

Thank you for your interest! This document outlines the process and guidelines for contributing to the project. By following these guidelines, you can help ensure a smooth collaboration process and a consistent codebase.

## Table of Content

- [Reporting a bug](#reporting-a-bug)
- [Requesting new features or discussing the project](#requesting-new-features-or-discussing-the-project)
- [Writing code](#writing-code)
  - [Requirements](#requirements)
  - [Installation](#installation)
  - [Branch naming](#branch-naming)
  - [Commit messages format](#commit-messages-format)
  - [Submitting changes](#submitting-changes)
  - [Feedback and reviews](#feedback-and-reviews)

## Reporting a bug

Before opening a new issue, please ensure it isn't a duplicate.

## Requesting new features or discussing the project

Before opening a new issue, please ensure it isn't a duplicate.

## Writing code

If you want to submit a fix or propose a new feature, follow the guidelines below.

### Requirements

- Python 3.10 or greater
- [`Poetry`](https://python-poetry.org/)

### Installation

1. Clone the repository and change it to your working directory.

2. Install the project:

   ```console
   $ poetry install
   ```

3. Activate the virtual environment:

   ```console
   $ poetry shell
   ```

4. Install the [`pre-commit`](https://pre-commit.com/) hooks by running:

   ```console
   $ pre-commit install
   ```

   Formatting and linting tools will run before each commit.

### Branch naming

Branch names should be descriptive and follow the format below:

```
<type>/<short-description>
```

- **type**: Describes the nature of the branch (e.g., `feature`, `fix`, `docs`, `refactor`).
- **short description**: A short description of the branch's purpose, using kebab-case.

### Commit messages format

Commit messages should be clear and descriptive. They should follow the format below:

```
<type>[(<scope>)]: <short description>
```

- **type**: Describes the nature of the change (e.g., `fix`, `feature`, `docs`, `refactor`).
- **scope** (optional): The part of the codebase the change affects (e.g., `parsing`).
- **short description**: A short description of the change.

### Submitting changes

1. **Create a new branch**: Create a new branch based on the `main` branch following the [convention above](#branch-naming).

2. **Make your changes**: Implement your changes.

3. **Commit your changes**: Commit your changes following the [required format](#commit-messages-format).

4. **Pull from upstream**: Before pushing your changes, pull the latest changes from the `upstream` main branch:

   ```sh
   git pull upstream main
   ```

5. **Push to your fork**: Push your branch to your forked repository.

6. **Open a pull request**: Go to the original repository and open a pull request from your branch. Ensure that your PR is descriptive, mentioning the changes made and their purpose.

### Feedback and reviews

Once your pull request is submitted, maintainers or contributors might provide feedback. Address any comments, make necessary changes, and push those updates to your branch.
