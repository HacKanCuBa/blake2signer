"""Common tasks for Invoke."""

import os
from tempfile import mkstemp

from invoke import UnexpectedExit
from invoke import task


@task
def flake8(ctx):
    """Run flake8 with proper exclusions."""
    ctx.run(f'flake8 --exclude tests blake2signer/', echo=True)
    ctx.run(f'flake8 --ignore=S101,R701,C901 blake2signer/tests/', echo=True)


@task
def pydocstyle(ctx):
    """Run pydocstyle with proper exclusions."""
    ctx.run('pydocstyle --explain blake2signer/', echo=True)


@task
def bandit(ctx):
    """Run bandit with proper exclusions."""
    ctx.run(f'bandit -i -r -x tests blake2signer/', echo=True)
    ctx.run(f'bandit -i -r -s B101 blake2signer/tests/', echo=True)


@task
def mypy(ctx):
    """Hint code with mypy."""
    ctx.run(f'mypy blake2signer/', echo=True, pty=True)


@task
def yapf(ctx, diff=False):
    """Run yapf to format the code."""
    cmd = ['yapf', '-r', '-vv']
    if diff:
        cmd.append('-d')
    else:
        cmd.append('-i')

    cmd.append('blake2signer/')
    ctx.run(' '.join(cmd))


@task
def trailing_commas(ctx):
    """Add missing trailing commas or remove it if necessary."""
    cmd = f'find blake2signer/ -type f -name "*.py" -exec add-trailing-comma "{{}}" \\+'
    ctx.run(cmd, echo=True, pty=True, warn=True)


# noinspection PyUnusedLocal
@task(yapf, trailing_commas)
def reformat(ctx):
    """Reformat code."""


# noinspection PyUnusedLocal
@task(flake8, pydocstyle, mypy, bandit)
def lint(ctx):
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
    ctx.run('find . -type d -name "__pycache__" -exec rm -rf "{}" \\+', echo=True)
    ctx.run('find . -type f -name "*.pyc" -delete', echo=True)


@task(
    aliases=['test'],
    help={
        'watch': 'run tests continuously with pytest-watch',
        'seed': 'seed number to repeat a randomization sequence',
    }
)
def tests(ctx, watch=False, seed=0):
    """Run tests."""
    if watch:
        cmd = ['pytest-watch', '--']
    else:
        cmd = ['pytest', '--suppress-no-test-exit-code']

    if seed:
        cmd.append(f'--randomly-seed={seed}')

    ctx.run(' '.join(cmd), pty=True)


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
    }
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
