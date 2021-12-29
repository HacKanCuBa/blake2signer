# Contribute

This section is intended for those who wish to contribute to this project. You can contribute in many ways:

* Reporting problems of any kind: things not working correctly, wrong/missing docs, etc.
* Solving existing issues.
* Creating PRs with code/docs/etc.
* Forking this project to create your own.
* Becoming a project maintainer.

To do so, you have to agree with the following *Code of Conduct*.

## Code of conduct

This Code of Conduct is adapted from the [Contributor Covenant](https://www.contributor-covenant.org/), [version 2.0](https://www.contributor-covenant.org/version/2/0/code_of_conduct.html).

### Our Pledge

We as members, contributors, and leaders pledge to make participation in our community a harassment-free experience for everyone, regardless of age, body size, visible or invisible disability, ethnicity, sex characteristics, gender identity and expression, level of experience, education, socio-economic status, nationality, personal appearance, race, religion, or sexual identity and orientation.

We pledge to act and interact in ways that contribute to an open, welcoming, diverse, inclusive, and healthy community.

### Our Standards

Examples of behavior that contributes to a positive environment for our community include:

* Demonstrating empathy and kindness toward other people
* Being respectful of differing opinions, viewpoints, and experiences
* Giving and gracefully accepting constructive feedback
* Accepting responsibility and apologizing to those affected by our mistakes, and learning from the experience
* Focusing on what is best not just for us as individuals, but for the overall community

Examples of unacceptable behavior include:

* The use of sexualized language or imagery, and sexual attention or advances of any kind
* Trolling, insulting or derogatory comments, and personal or political attacks
* Public or private harassment
* Publishing others' private information, such as a physical or email address, without their explicit permission
* Other conduct which could reasonably be considered inappropriate in a professional setting

## Developing

Start your local dev environment by activating the virtualenv. I recommend using [pyenv](https://github.com/pyenv/pyenv), but whatever suits your needs is fine. Don't worry about Python versions, use any of the supported ones. The pipeline will test the rest of them.

After that, install dependencies with `poetry install --remove-untracked`.

### Making PRs

Write your code. Then create a changelog fragment using `scriv create` with a short description of your changes in the corresponding category (added, changed, fixed, etc.).  
You must include the necessary docstrings and unit tests so that coverage remains 100%.

It is preferred to contribute with short, reviewable commits rather than huge changes.

Finally, the following commands must succeed locally:

* `inv reformat`: format code using YAPF.
* `inv lint`: static analysis for compliance of PEP8, PEP257, PEP287 and many more.
* `inv tests`: run the tests' battery.
* `inv safety`: run a security analysis over dependencies using `safety`.

You can alternatively run `inv commit` to run all the above and commit afterwards.

If the linter complains about *code too complex*, run `inv cc -c` (or the long expression `inv cyclomatic-complexity --complex`) for more information.

### Working under PyPy

You can install and run this package in PyPy without issues but if you are using PyPy to contribute to this project, you probably noticed that running `poetry install` fails: that's due to a `mypy` dependency, `typed_ast`, which [will probably never work under PyPy](https://github.com/python/typed_ast/issues/111). What you can do is `poetry remove --dev mypy` and let the pipeline run `mypy` for you.

Other than that I once tried to run the [performance tests](https://blake2signer.hackan.net/en/stable/comparison/#performance-comparison), and my machine froze during the serializer tests because it exhausted the memory. I tried again using fewer iterations, and it worked.

### Working under Stackless

You can install and run this package in Stackless without issues but if you are using Stackless to contribute to this project, you probably noticed that running `inv tests` fails with a segmentation fault: I have no idea what causes it, but it is related to `coverage` and `pytest`. The solution is to run `pytest --no-cov` directly, and letting the pipeline show the coverage for you.

## Releasing new versions

I choose to stick with [semver](https://semver.org/), which is compatible with [PEP440](https://www.python.org/dev/peps/pep-0440/) (but only the syntax for version core).

Once everything is ready for release, follow these steps:

1. Create a new release branch from `develop`: `git flow release start <M.m.p>`
1. Edit `pyproject.toml` and change `version` (you can use `poetry version major|minor|patch` accordingly to one-up said version part).
1. Edit `blake2signer/__init__.py` and change `__version__`: `__version__ = '<M.m.p>'`.
1. Collect changelog fragments: `scriv collect`.
1. Edit the changelog to properly indicate the version.
1. Copy the edition to the changelog in the docs.
1. If necessary, write the upgrade guide in the docs.
1. Commit, push branch and create MR to `main`. A CI job will publish the package to Test PyPy as a prerelease. If something went wrong, fix, commit and push again; the CI job will change the release number and publish it again.
1. Merge into `main` and create MR to `develop`.
1. Merge into `develop`, create and push signed tag: `git tag -s <M.m.p>`. A CI job will publish the package to PyPi.
1. Create release in Gitlab and [properly sign packages](https://gist.github.com/HacKanCuBa/6fabded3565853adebf3dd140e72d33e).
