"""Common tasks for Invoke."""

import os
import typing
from functools import partial
from tempfile import mkstemp
from unittest.mock import patch

from invoke import UnexpectedExit
from invoke import task

from blake2signer import Blake2SerializerSigner
from blake2signer import Blake2Signer
from blake2signer import Blake2TimestampSigner
# noinspection PyProtectedMember
from blake2signer import __version__


@task
def flake8(ctx):
    """Run flake8 with proper exclusions."""
    ctx.run('flake8 --exclude tests blake2signer/', echo=True)
    ctx.run('flake8 --ignore=S101,R701,C901 blake2signer/tests/', echo=True)
    ctx.run('flake8 --ignore=S101,R701,C901 tests/', echo=True)
    ctx.run('flake8 tasks.py', echo=True)


@task
def pydocstyle(ctx):
    """Run pydocstyle with proper exclusions."""
    ctx.run('pydocstyle --explain blake2signer/', echo=True)
    ctx.run('pydocstyle --explain tests/', echo=True)
    ctx.run('pydocstyle --explain tasks.py', echo=True)


@task
def darglint(ctx):
    """Run darglint."""
    ctx.run('darglint -v2 blake2signer/', echo=True)
    ctx.run('darglint -v2 tests/', echo=True)
    ctx.run('darglint -v2 tasks.py', echo=True)


@task
def bandit(ctx):
    """Run bandit with proper exclusions."""
    ctx.run('bandit -i -r -x blake2signer/tests blake2signer/', echo=True)
    ctx.run('bandit -i -r -s B101 blake2signer/tests/', echo=True)
    ctx.run('bandit -i -r -s B101 tests/', echo=True)
    ctx.run('bandit -i -r tasks.py', echo=True)


@task
def mypy(ctx):
    """Hint code with mypy."""
    ctx.run('mypy blake2signer/', echo=True, pty=True)
    ctx.run('mypy tests/', echo=True, pty=True)


@task
def yapf(ctx, diff=False):
    """Run yapf to format the code."""
    cmd = ['yapf', '-r', '-vv']
    if diff:
        cmd.append('-d')
    else:
        cmd.append('-i')

    cmd.append('blake2signer/')
    cmd.append('tests/')
    cmd.append('tasks.py')

    ctx.run(' '.join(cmd), echo=True)


@task
def trailing_commas(ctx):
    """Add missing trailing commas or remove it if necessary."""
    opts = r'-type f -name "*.py" -exec add-trailing-comma "{}" \+'  # noqa: P103
    ctx.run('find blake2signer/ ' + opts, echo=True, pty=True, warn=True)
    ctx.run('find tests/ ' + opts, echo=True, pty=True, warn=True)
    ctx.run('add-trailing-comma tasks.py', echo=True, pty=True, warn=True)


# noinspection PyUnusedLocal
@task(yapf, trailing_commas)
def reformat(ctx):  # pylint: disable=W0613
    """Reformat code."""


@task
def pylint(ctx):
    """Run pylint."""
    ctx.run('pylint blake2signer/ --ignore tests', echo=True, pty=True, warn=True)
    ctx.run('pylint blake2signer/tests/ --exit-zero', echo=True, pty=True, warn=True)
    ctx.run('pylint tests/ --exit-zero', echo=True, pty=True, warn=True)
    ctx.run('pylint tasks.py --exit-zero', echo=True, pty=True, warn=True)


# noinspection PyUnusedLocal
@task(flake8, pylint, pydocstyle, darglint, mypy, bandit)
def lint(ctx):  # pylint: disable=W0613
    """Lint code and static analysis."""


@task
def clean(ctx):
    """Remove all temporary and compiled files."""
    remove = (
        'build',
        'dist',
        '*.egg-info',
        '.coverage',
        'cover',
        'htmlcov',
        '.mypy_cache',
        '.pytest_cache',
        'site',
    )
    ctx.run(f'rm -vrf {" ".join(remove)}', echo=True)
    ctx.run(r'find . -type d -name "__pycache__" -exec rm -rf "{}" \+', echo=True)  # noqa: P103
    ctx.run('find . -type f -name "*.pyc" -delete', echo=True)


@task(
    aliases=['test'],
    help={
        'watch': 'run tests continuously with pytest-watch',
        'seed': 'seed number to repeat a randomization sequence',
    },
)
def tests(ctx, watch=False, seed=0, coverage=True):
    """Run tests."""
    if watch:
        cmd = ['pytest-watch', '--']
    else:
        cmd = ['pytest', '--suppress-no-test-exit-code']

    if seed:
        cmd.append(f'--randomly-seed={seed}')

    if not coverage:
        cmd.append('--no-cov')

    cmd0 = cmd + ['--ignore tests']
    cmd1 = cmd + ['--ignore blake2signer/tests']
    if coverage:
        cmd1.append('--cov-append')

    ctx.run(' '.join(cmd0), pty=True, echo=True)
    ctx.run(' '.join(cmd1), pty=True, echo=True)


@task
def safety(ctx):
    """Run Safety dependency vuln checker."""
    fd, requirements_path = mkstemp(prefix='b2s')
    os.close(fd)
    try:
        ctx.run(f'poetry export -f requirements.txt -o {requirements_path} --dev')
        ctx.run(f'safety check --full-report -r {requirements_path}')
    except UnexpectedExit:
        os.remove(requirements_path)
        raise

    os.remove(requirements_path)


@task(
    aliases=['cc'],
    help={
        'complex': 'filter results to show only potentially complex functions (B+)',
    },
)
def cyclomatic_complexity(ctx, complex_=False):
    """Analise code Cyclomatic Complexity using radon."""
    # Run Cyclomatic Complexity
    cmd = 'radon cc -s -a'
    if complex_:
        cmd += ' -nb'
    ctx.run(f'{cmd} blake2signer', pty=True)


@task(reformat, lint, tests, safety, aliases=['ci'])
def commit(ctx, amend=False):
    """Run all pre-commit commands and then commit staged changes."""
    cmd = ['git', 'commit']
    if amend:
        cmd.append('--amend')

    ctx.run(' '.join(cmd), pty=True)


@task(help={'build': 'Build the docs instead of serving them'})
def docs(ctx, build=False, verbose=False):
    """Serve the docs using mkdocs, alternatively building them."""
    args = ['mkdocs']

    if verbose:
        args.append('--verbose')

    if build:
        args.extend(['build', '--clean', '--strict'])
    else:
        args.append('serve')

    ctx.run(' '.join(args))


# noinspection PyUnusedLocal
@task
def check_compat(ctx):  # pylint: disable=W0613
    """Print current version signatures to check compatibility with previous versions."""

    def sign(
        signer: typing.Union[Blake2Signer, Blake2TimestampSigner, Blake2SerializerSigner],
        data_: str,
    ) -> str:
        """Sign data with given signer."""
        if isinstance(signer, Blake2SerializerSigner):
            return signer.dumps(data_)

        return signer.sign(data_).decode()

    secret = 'too many secrets!'  # noqa: S105  # nosec: B105
    data = 'is compat ensured?'
    partial_signers = (
        partial(Blake2Signer, secret, digest_size=16),
        partial(Blake2TimestampSigner, secret, digest_size=16),
        partial(Blake2SerializerSigner, secret, digest_size=16),
        partial(Blake2SerializerSigner, secret, digest_size=16, max_age=5),
    )
    print('current version:', __version__)
    print('Signer | Hasher | Signed value')
    for partial_signer in partial_signers:
        name = str(partial_signer.func).split('.')[2].rstrip("'>")
        for hasher in ('blake2b', 'blake2s', 'blake3'):
            with patch('blake2signer.bases.time', return_value=531810000):
                print(
                    name,
                    '|',
                    hasher,
                    '|',
                    sign(partial_signer(hasher=hasher), data),
                )
