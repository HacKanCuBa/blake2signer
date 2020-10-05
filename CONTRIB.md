# Contributors

This section is intended for those who wish to contribute to this project. You can contribute in many ways:

* Reporting problems of any kind: things not working correctly, wrong/missing docs, etc.
* Solving existing issues.
* Creating PRs with code/docs/etc.
* Forking this project to create your own.
* Becoming a project maintainer.

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
* Accepting responsibility and apologizing to those affected by our mistakes,
  and learning from the experience
* Focusing on what is best not just for us as individuals, but for the
  overall community

Examples of unacceptable behavior include:

* The use of sexualized language or imagery, and sexual attention or advances of any kind
* Trolling, insulting or derogatory comments, and personal or political attacks
* Public or private harassment
* Publishing others' private information, such as a physical or email address, without their explicit permission
* Other conduct which could reasonably be considered inappropriate in a professional setting

## Making PRs

For a pull request of whatever change you want to do, the following commands must succeed locally:

* `inv reformat`: format code using YAPF.
* `inv lint`: static analysis for compliance of PEP8, PEP257, PEP287 and many more.
* `inv tests`: run the tests battery.
* `inv safety`: run a security analysis over dependencies using `safety`.

You can alternatively run `inv commit` to run all of the above and commit afterwards.

If the linter complains about *code too complex*, run `inv cc -c` (or the long expression `inv cyclomatic-complexity --complex`) for more information.

Create a changelog fragment using `scriv create` and write a short description of your changes in the correct category (added, changed, fixed, etc.).

Your PR must include the necessary docstrings and unit tests so that coverage remains 100%.

### Releasing new versions

I choose to stick with [semver](https://semver.org/), which is compatible with [PEP440](https://www.python.org/dev/peps/pep-0440/) (but only the syntax for version core).  

Once everything is ready for release, follow these steps:

1. Create a new release branch from `develop`: `git flow release start <M.m.p>`
1. Edit `pyproject.toml` and change `version` (you can use `poetry major|minor|patch` accordingly to one-up said version part).
1. Edit `blake2signer/__init__.py` and change `__version__`: `__version__ = '<M.m.p>'`.
1. Collect changelog fragments: `scriv collect`.
1. Edit the changelog to properly indicate the version.
1. Commit and push, create MR to `main`.
1. Merge into `main`, create MR to `develop`.
1. Merge into `develop`, create and push signed tag: `git tag -s <M.m.p>`.
1. Build packages to publish: `poetry build`.
1. Publish to testpypi: `poetry publish -r testpypi` or `twine upload -r testpypi dist/*`.
1. Check published package and if all went well, publish: `poetry publish` or `twine upload dist/*`.
1. Create release in Gitlab and [properly sign packages](https://gist.github.com/HacKanCuBa/6fabded3565853adebf3dd140e72d33e).
