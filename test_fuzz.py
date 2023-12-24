"""Test fuzzing script.

We are only testing helper, and main functions, not the actual fuzzing ones, because it
makes little sense to do so.
"""
import sys
from typing import Any
from typing import Dict
from typing import Generator
from unittest import mock

import pytest

import fuzz  # noqa: I100, I202
from blake2signer.errors import InvalidOptionError  # noqa: I201
from blake2signer.errors import MissingDependencyError
from blake2signer.errors import UnsignedDataError
from blake2signer.hashers import HasherChoice


@pytest.fixture
def mock_pythonfuzz() -> Generator[mock.MagicMock, None, None]:
    """Mock pythonfuzz package, getting a mocked PythonFuzz decorator."""
    module_name = 'pythonfuzz.main'
    old_module = sys.modules.get(module_name)
    module = mock.MagicMock()
    sys.modules[module_name] = module

    yield module

    if old_module is not None:
        sys.modules[module_name] = old_module


@pytest.mark.parametrize(
    'signer_kwargs',
    (
        {},
        {
            'serializer': mock.MagicMock(),
        },
    ),
)
def test_get_signer_happy_path(signer_kwargs: Dict[str, Any]) -> None:
    """Test that get_signer works."""
    hasher = HasherChoice.blake2s
    klass = mock.MagicMock()
    secret = b'secret'
    signer = fuzz.get_signer(klass, hasher=hasher, secret=secret, **signer_kwargs)  # type: ignore

    assert isinstance(signer, mock.MagicMock)
    klass.assert_called_once_with(secret, hasher=hasher, **signer_kwargs)


def test_get_signer_wrong_secret() -> None:
    """Test that get_signer gets/sets the global signers collection."""
    hasher = HasherChoice.blake2s
    klass = mock.MagicMock(side_effect=[InvalidOptionError, mock.DEFAULT, InvalidOptionError])
    klass.__name__ = 'MagicMock'
    klass.MIN_SECRET_SIZE = 8
    secret = b'secret'

    with mock.patch.object(fuzz, 'signers_ctx') as mock_signers_ctx:
        mock_signers_ctx.get.return_value = {}

        signer = fuzz.get_signer(klass, hasher=hasher, secret=secret)  # type: ignore

        assert isinstance(signer, mock.MagicMock)
        klass.assert_has_calls(
            [
                mock.call(secret, hasher=hasher),
                mock.call(b's' * klass.MIN_SECRET_SIZE, hasher=hasher),
            ],
        )

    mock_signers_ctx.get.assert_called_once_with()
    mock_signers_ctx.set.assert_called_once_with({
        f'MagicMock_{hasher.value}': signer,
    })

    klass.reset_mock()
    with mock.patch.object(fuzz, 'signers_ctx') as mock_signers_ctx:
        mock_signers_ctx.get.return_value = {
            f'MagicMock_{hasher.value}': signer,
        }

        new_signer = fuzz.get_signer(klass, hasher=hasher, secret=secret)  # type: ignore

    assert new_signer is signer  # We got the stored one

    mock_signers_ctx.get.assert_called_once_with()
    mock_signers_ctx.set.assert_not_called()


def test_kbinterrupt_handler_happy_path(capsys: pytest.CaptureFixture) -> None:
    """Test that kbinterrupt_handler exits with given signal number."""
    with pytest.raises(SystemExit) as cm:  # pylint: disable=C0103
        fuzz.kbinterrupt_handler(2, None)

    assert 130 == cm.value.code
    assert '\nProcess interrupted!\n' == capsys.readouterr().out


def test_check_signing_happy_path() -> None:
    """Test check_signing happy path."""
    data = b'1234'
    sign = mock.MagicMock(return_value=b'abcd')
    unsign = mock.MagicMock(return_value=data)

    fuzz.check_signing(data, sign=sign, unsign=unsign)

    sign.assert_called_once_with(data)
    unsign.assert_called_once_with(sign.return_value)


def test_check_signing_data_mismatch() -> None:
    """Test that check_signing raising ValueError on data mismatch."""
    data = b'1234'
    sign = mock.MagicMock(return_value=b'abcd')
    unsign = mock.MagicMock(return_value=b'abcd')

    with pytest.raises(ValueError, match='data mismatch'):
        fuzz.check_signing(data, sign=sign, unsign=unsign)

    sign.assert_called_once_with(data)
    unsign.assert_called_once_with(sign.return_value)


def test_check_signing_unsigned_data_error() -> None:
    """Test that check_signing does nothing on UnsignedDataError."""
    data = b'1234'
    sign = mock.MagicMock(side_effect=UnsignedDataError)
    unsign = mock.MagicMock()

    fuzz.check_signing(data, sign=sign, unsign=unsign)

    sign.assert_called_once_with(data)
    unsign.assert_not_called()


def test_import_pythonfuzz_with_package(
    mock_pythonfuzz: mock.MagicMock,  # pylint: disable=W0621
) -> None:
    """Test that import_pythonfuzz imports pythonfuzz if it exists."""

    def func(_: bytes) -> None:
        """Test func."""

    with mock.patch.object(fuzz.importlib.util, 'find_spec') as mock_get_distribution:
        pythonfuzz = fuzz.import_pythonfuzz()

    mock_get_distribution.assert_called_once_with('pythonfuzz')

    pythonfuzz(func)
    mock_pythonfuzz.PythonFuzz.assert_called_once_with(func)


def test_import_pythonfuzz_without_package() -> None:
    """Test that import_pythonfuzz won't fail if the package doesn't exist until it's used."""
    with mock.patch.object(
            fuzz.importlib.util,
            'find_spec',
            return_value=None,
    ):
        pythonfuzz = fuzz.import_pythonfuzz()  # No exception raised

    with pytest.raises(MissingDependencyError, match='pythonfuzz can not be used if'):
        pythonfuzz(lambda _: None)


def test_fuzz_decorator() -> None:
    """Test that the fuzz decorator imports pythonfuzz when called."""

    def func(_: bytes) -> None:
        """Test func."""

    wrapped = fuzz.fuzz(func)

    with mock.patch.object(fuzz, 'import_pythonfuzz') as mock_import_pythonfuzz:
        wrapped()

    mock_import_pythonfuzz.return_value.assert_called_once_with(func)
    mock_import_pythonfuzz.return_value.return_value.assert_called_once_with()


def test_main_happy_path(capsys: pytest.CaptureFixture) -> None:
    """Test that main properly calls the fuzzer."""
    fuzz_test = mock.MagicMock()
    with mock.patch.object(fuzz.sys, 'argv', new=['fuzz', 'test']):
        with mock.patch.object(
                fuzz,
                'globals',
                return_value={
                    'fuzz_test': fuzz_test,
                },
        ):
            fuzz.main()

    fuzz_test.assert_called_once_with()
    assert 'Fuzzing for test ...\n' == capsys.readouterr().out


def test_main_not_enough_args(capsys: pytest.CaptureFixture) -> None:
    """Test that main shows usage when args are not enough."""
    with mock.patch.object(fuzz.sys, 'argv', new=['fuzz']):
        with pytest.raises(SystemExit) as cm:  # pylint: disable=C0103
            fuzz.main()

    assert cm.value.code == 1

    expected_out = (
        'Usage: fuzz <signer> [fuzzer args...]\n',
        'Where signer is one of the signers provided by this package\n',
    )
    assert ''.join(expected_out) == capsys.readouterr().out


def test_main_no_fuzzer(capsys: pytest.CaptureFixture) -> None:
    """Test that main shows error when there's no fuzzer."""
    with mock.patch.object(fuzz.sys, 'argv', new=['fuzz', 'test']):
        with pytest.raises(SystemExit) as cm:  # pylint: disable=C0103
            fuzz.main()

    assert cm.value.code == 1

    expected_out = (
        'Signer does not exist or can not be fuzzed: fuzzer not implemented for test\n',
    )
    assert ''.join(expected_out) == capsys.readouterr().out
