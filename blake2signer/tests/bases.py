"""Base classes to test signers."""

import hashlib
import re
import typing
from abc import ABC
from abc import abstractmethod

import pytest
from packaging.version import parse as version_parse

from .. import errors
from ..bases import Blake2Signature
from ..bases import Blake2SignatureDump
from ..bases import HasherChoice
from ..bases import Secret
from ..encoders import B32Encoder
from ..encoders import B64URLEncoder
from ..encoders import HexEncoder
from ..hashers import BLAKE2Hasher
from ..hashers import BLAKE3Hasher
from ..hashers import BLAKEHasher
from ..hashers import has_blake3
from ..interfaces import EncoderInterface
from ..signers import Blake2SerializerSigner
from ..signers import Blake2Signer
from ..signers import Blake2TimestampSigner

Signer = typing.Union[Blake2Signer, Blake2TimestampSigner, Blake2SerializerSigner]

Signature = typing.Union[Blake2SignatureDump, Blake2Signature]


class BaseTests(ABC):
    """Base class for tests."""

    secret = b'0123456789012345'
    person = b'acab'

    @property
    def data(self) -> typing.AnyStr:
        """Get test data."""
        data = b'datadata'
        return data if self.signature_type is bytes else data.decode()

    @property
    @abstractmethod
    def signer_class(self) -> typing.Type[Signer]:
        """Get the signer class to test."""

    def signer(
        self,
        secret: typing.Union[Secret, typing.Sequence[Secret], None] = None,
        **kwargs: typing.Any,
    ) -> Signer:
        """Get the signer to test."""
        return self.signer_class(self.secret if secret is None else secret, **kwargs)

    @property
    @abstractmethod
    def signature_type(self) -> typing.Type[typing.Union[str, bytes]]:
        """Get the signature type for the signer, either `str` or `bytes`."""

    @typing.overload
    def sign(
        self,
        signer: Blake2Signer,
        data: typing.Any,
        **kwargs: typing.Any,
    ) -> bytes:
        """Sign data with the signer."""

    @typing.overload
    def sign(
        self,
        signer: Blake2TimestampSigner,
        data: typing.Any,
        **kwargs: typing.Any,
    ) -> bytes:
        """Sign data with the signer."""

    @typing.overload
    def sign(
        self,
        signer: Blake2SerializerSigner,
        data: typing.Any,
        **kwargs: typing.Any,
    ) -> str:
        """Sign data with the signer."""

    @abstractmethod
    def sign(
        self,
        signer: Signer,
        data: typing.Any,
        **kwargs: typing.Any,
    ) -> typing.AnyStr:
        """Sign data with the signer."""

    @typing.overload
    def unsign(
        self,
        signer: Blake2Signer,
        signed_data: typing.AnyStr,
        **kwargs: typing.Any,
    ) -> bytes:
        """Unsign signed data with the signer."""

    @typing.overload
    def unsign(
        self,
        signer: Blake2TimestampSigner,
        signed_data: typing.AnyStr,
        **kwargs: typing.Any,
    ) -> bytes:
        """Unsign signed data with the signer."""

    @typing.overload
    def unsign(
        self,
        signer: Blake2SerializerSigner,
        signed_data: typing.AnyStr,
        **kwargs: typing.Any,
    ) -> typing.Any:
        """Unsign signed data with the signer."""

    @abstractmethod
    def unsign(
        self,
        signer: Signer,
        signed_data: typing.AnyStr,
        **kwargs: typing.Any,
    ) -> typing.Any:
        """Unsign signed data with the signer."""

    @typing.overload
    def sign_parts(
        self,
        signer: Blake2Signer,
        data: typing.Any,
        **kwargs: typing.Any,
    ) -> Blake2Signature:
        """Sign data with the signer in parts."""

    @typing.overload
    def sign_parts(
        self,
        signer: Blake2TimestampSigner,
        data: typing.Any,
        **kwargs: typing.Any,
    ) -> Blake2Signature:
        """Sign data with the signer in parts."""

    @typing.overload
    def sign_parts(
        self,
        signer: Blake2SerializerSigner,
        data: typing.Any,
        **kwargs: typing.Any,
    ) -> Blake2SignatureDump:
        """Sign data with the signer in parts."""

    @abstractmethod
    def sign_parts(
        self,
        signer: Signer,
        data: typing.Any,
        **kwargs: typing.Any,
    ) -> Signature:
        """Sign data with the signer in parts."""

    @typing.overload
    def unsign_parts(
        self,
        signer: Blake2Signer,
        signature: Signature,
        **kwargs: typing.Any,
    ) -> bytes:
        """Unsign signature with the signer."""

    @typing.overload
    def unsign_parts(
        self,
        signer: Blake2TimestampSigner,
        signature: Signature,
        **kwargs: typing.Any,
    ) -> bytes:
        """Unsign signature with the signer."""

    @typing.overload
    def unsign_parts(
        self,
        signer: Blake2SerializerSigner,
        signature: Signature,
        **kwargs: typing.Any,
    ) -> typing.Any:
        """Unsign signature with the signer."""

    @abstractmethod
    def unsign_parts(
        self,
        signer: Signer,
        signature: Signature,
        **kwargs: typing.Any,
    ) -> typing.Any:
        """Unsign signature with the signer."""

    @staticmethod
    def trick_sign(signer: Signer, data: typing.AnyStr) -> bytes:
        """Sign data properly as if using `Blake2Signer.sign()`.

        This function is useful to trick a signer into unsigning something that
        normally wouldn't be possible because of different safeguard checks.

        Args:
            signer: The signer to use.
            data: data to be signed.

        Returns:
            Signed data, like `signer.sign(data)`, but bypassing checks if any.
        """
        # noinspection PyProtectedMember
        data_b = signer._force_bytes(data)

        # noinspection PyProtectedMember
        return signer._compose(data_b, signature=signer._sign(data_b))

    @pytest.fixture
    def signer_min_digest_size_changed(self) -> typing.Type[Signer]:
        """Fixture to obtain a signer class with a non-default min digest size limit."""
        signer_class = self.signer_class
        min_digest_size = signer_class.MIN_DIGEST_SIZE

        signer_class.MIN_DIGEST_SIZE = 4
        yield signer_class

        signer_class.MIN_DIGEST_SIZE = min_digest_size

    @pytest.fixture
    def signer_min_secret_size_changed(self) -> typing.Type[Signer]:
        """Fixture to obtain a signer class with a non-default min secret size limit."""
        signer_class = self.signer_class
        min_secret_size = signer_class.MIN_SECRET_SIZE

        signer_class.MIN_SECRET_SIZE = 4
        yield signer_class

        signer_class.MIN_SECRET_SIZE = min_secret_size

    def mix_signers_sign_unsign(self, signer1: Signer, signer2: Signer) -> None:
        """Sign and unsign mixing signers to check it fails correctly."""
        signed1 = self.sign(signer1, self.data)
        with pytest.raises(errors.InvalidSignatureError) as exc:
            self.unsign(signer2, signed1)
        assert exc.value.__cause__ is None

        signed2 = self.sign(signer2, self.data)
        with pytest.raises(errors.InvalidSignatureError) as exc:
            self.unsign(signer1, signed2)
        assert exc.value.__cause__ is None

    def test_defaults(self) -> None:
        """Test defaults are correct and work as-is."""
        signer = self.signer()

        assert isinstance(signer, self.signer_class)
        assert isinstance(signer._hasher, BLAKE2Hasher)
        assert signer._hasher._hasher == hashlib.blake2b

        signed = self.sign(signer, self.data)
        assert isinstance(signed, self.signature_type)
        assert self.unsign(signer, signed) == self.data

        signature = self.sign_parts(signer, self.data)
        if self.signature_type is str:
            assert isinstance(signature, Blake2SignatureDump)
        else:
            assert isinstance(signature, Blake2Signature)
        assert self.unsign_parts(signer, signature) == self.data

    @pytest.mark.xfail(
        not has_blake3(),
        reason='blake3 is not installed',
        raises=errors.MissingDependencyError,
    )
    @pytest.mark.parametrize(
        ('hasher', 'hasher_class'),
        (
            (HasherChoice.blake2b, BLAKE2Hasher),
            (HasherChoice.blake2s, BLAKE2Hasher),
            (HasherChoice.blake3, BLAKE3Hasher),
        ),
    )
    def test_hasher_can_be_changed(
        self,
        hasher: HasherChoice,
        hasher_class: typing.Type[BLAKEHasher],
    ) -> None:
        """Test that the hasher can be changed and works correctly."""
        signer = self.signer(hasher=hasher)

        assert isinstance(signer, self.signer_class)
        assert isinstance(signer._hasher, hasher_class)

        signed = self.sign(signer, self.data)
        assert isinstance(signed, self.signature_type)
        assert self.unsign(signer, signed) == self.data

    def test_wrong_hasher_choice(self) -> None:
        """Test wrong hasher choice."""
        with pytest.raises(errors.InvalidOptionError, match='invalid hasher choice'):
            self.signer(hasher='blake2')

    def test_all_instantiation_params_can_be_changed(self) -> None:
        """Test correct signing and unsigning using all non-default options."""
        signer = self.signer(
            self.secret,
            personalisation=self.person,
            hasher=self.signer_class.Hashers.blake2s,
            digest_size=32,
            deterministic=True,
            separator=',',
            encoder=B32Encoder,
        )

        assert isinstance(signer, self.signer_class)

        signed = self.sign(signer, self.data)
        assert isinstance(signed, self.signature_type)
        assert self.unsign(signer, signed) == self.data

        signature = self.sign_parts(signer, self.data)
        assert isinstance(signature.data, self.signature_type)
        assert isinstance(signature.signature, self.signature_type)
        if self.signature_type is str:
            assert isinstance(signature, Blake2SignatureDump)
        else:
            assert isinstance(signature, Blake2Signature)
            assert self.data == signature.data

        assert self.unsign_parts(signer, signature) == self.data

    @pytest.mark.xfail(
        not has_blake3(),
        reason='blake3 is not installed',
        raises=errors.MissingDependencyError,
    )
    @pytest.mark.parametrize(
        'hasher',
        (
            HasherChoice.blake2b,
            HasherChoice.blake2s,
            HasherChoice.blake3,
        ),
    )
    def test_sign_unsign_with_person(self, hasher: HasherChoice) -> None:
        """Test signing and unsigning using person is correct."""
        signer = self.signer(personalisation=self.person, hasher=hasher)

        assert self.data == self.unsign(signer, self.sign(signer, self.data))

    @pytest.mark.xfail(
        not has_blake3(),
        reason='blake3 is not installed',
        raises=errors.MissingDependencyError,
    )
    @pytest.mark.parametrize(
        'hasher',
        (
            HasherChoice.blake2b,
            HasherChoice.blake2s,
            HasherChoice.blake3,
        ),
    )
    def test_sign_unsign_with_different_person(self, hasher: HasherChoice) -> None:
        """Test signing and unsigning using different person fails correctly."""
        signer1 = self.signer(personalisation=self.person, hasher=hasher)
        signer2 = self.signer(personalisation=self.person * 2, hasher=hasher)

        self.mix_signers_sign_unsign(signer1, signer2)

    @pytest.mark.xfail(
        not has_blake3(),
        reason='blake3 is not installed',
        raises=errors.MissingDependencyError,
    )
    @pytest.mark.parametrize(
        'hasher',
        (
            HasherChoice.blake2b,
            HasherChoice.blake2s,
            HasherChoice.blake3,
        ),
    )
    def test_sign_unsign_with_different_encoder(self, hasher: HasherChoice) -> None:
        """Test signing and unsigning using different encoder fails correctly."""
        signer1 = self.signer(encoder=B64URLEncoder, hasher=hasher)
        signer2 = self.signer(encoder=B32Encoder, hasher=hasher)

        self.mix_signers_sign_unsign(signer1, signer2)

    @pytest.mark.parametrize(
        ('secret', 'person', 'separator', 'data'),
        (
            ('setec astronomy.', 'acab', ',', 'datadata'),
            (b'setec astronomy.', 'acab', ',', 'datadata'),
            ('setec astronomy.', b'acab', ',', 'datadata'),
            ('setec astronomy.', 'acab', b',', 'datadata'),
            ('setec astronomy.', b'acab', b',', 'datadata'),
            (b'setec astronomy.', b'acab', b',', 'datadata'),
        ),
    )
    def test_string_instead_of_bytes_inputs(
        self,
        secret: typing.Union[str, bytes],
        person: typing.Union[str, bytes],
        separator: typing.Union[str, bytes],
        data: typing.Union[str, bytes],
    ) -> None:
        """Test non-bytes values for parameters such as secret, person, data, etc."""
        signer = self.signer(
            secret,
            personalisation=person,
            separator=separator,
        )
        assert isinstance(signer, self.signer_class)

        signed = self.sign(signer, data)
        assert isinstance(signed, self.signature_type)
        if isinstance(separator, self.signature_type):
            assert separator in signed
        elif isinstance(separator, bytes):
            assert separator.decode() in signed
        else:
            assert separator.encode() in signed

        unsigned = self.unsign(signer, signed)
        if isinstance(data, self.signature_type):
            assert data == unsigned
        else:
            assert data == unsigned.decode()

        # Now change `signed` type and check if it works correctly
        if self.signature_type is bytes:
            unsigned = self.unsign(signer, signed.decode())
        else:
            unsigned = self.unsign(signer, signed.encode())
        if isinstance(data, self.signature_type):
            assert data == unsigned
        else:
            assert data == unsigned.decode()

    @pytest.mark.xfail(
        not has_blake3(),
        reason='blake3 is not installed',
        raises=errors.MissingDependencyError,
    )
    @pytest.mark.parametrize(
        'hasher',
        (
            HasherChoice.blake2b,
            HasherChoice.blake2s,
            HasherChoice.blake3,
        ),
    )
    def test_sign_is_unique_non_deterministic(self, hasher: HasherChoice) -> None:
        """Test that each signing is unique because of salt."""
        signer = self.signer(deterministic=False, hasher=hasher)

        signed1 = self.sign(signer, self.data)
        signed2 = self.sign(signer, self.data)

        assert len(signed1) == len(signed2)
        assert type(signed1) == type(signed2)
        assert signed1[-len(self.data):] == signed2[-len(self.data):]
        assert signed1 != signed2

        unsigned1 = self.unsign(signer, signed1)
        assert self.data == unsigned1

        unsigned2 = self.unsign(signer, signed2)
        assert self.data == unsigned2

    @pytest.mark.xfail(
        not has_blake3(),
        reason='blake3 is not installed',
        raises=errors.MissingDependencyError,
    )
    @pytest.mark.parametrize(
        'hasher',
        (
            HasherChoice.blake2b,
            HasherChoice.blake2s,
            HasherChoice.blake3,
        ),
    )
    def test_sign_unsign_deterministic(self, hasher: HasherChoice) -> None:
        """Test sign and unsign with a deterministic signature."""
        signer = self.signer(deterministic=True, hasher=hasher)

        signed1 = self.sign(signer, self.data)
        signed2 = self.sign(signer, self.data)
        assert signed1 == signed2

        unsigned = self.unsign(signer, signed1)
        assert self.data == unsigned

    @pytest.mark.xfail(
        not has_blake3(),
        reason='blake3 is not installed',
        raises=errors.MissingDependencyError,
    )
    @pytest.mark.parametrize(
        'hasher',
        (
            HasherChoice.blake2b,
            HasherChoice.blake2s,
            HasherChoice.blake3,
        ),
    )
    def test_sign_parts_is_unique_non_deterministic(self, hasher: HasherChoice) -> None:
        """Test that each signing in parts is unique because of salt."""
        signer = self.signer(deterministic=False, hasher=hasher)

        signature1 = self.sign_parts(signer, self.data)
        signature2 = self.sign_parts(signer, self.data)
        assert signature1 != signature2

        unsigned = self.unsign_parts(signer, signature1)
        assert self.data == unsigned

        unsigned = self.unsign_parts(signer, signature2)
        assert self.data == unsigned

    @pytest.mark.xfail(
        not has_blake3(),
        reason='blake3 is not installed',
        raises=errors.MissingDependencyError,
    )
    @pytest.mark.parametrize(
        'hasher',
        (
            HasherChoice.blake2b,
            HasherChoice.blake2s,
            HasherChoice.blake3,
        ),
    )
    def test_sign_unsign_parts_deterministic(self, hasher: HasherChoice) -> None:
        """Test signing and unsigning in parts deterministically."""
        signer = self.signer(deterministic=True, hasher=hasher)

        signature1 = self.sign_parts(signer, self.data)
        signature2 = self.sign_parts(signer, self.data)
        assert signature1 == signature2

        unsigned = self.unsign_parts(signer, signature1)
        assert self.data == unsigned

    @pytest.mark.xfail(
        not has_blake3(),
        reason='blake3 is not installed',
        raises=errors.MissingDependencyError,
    )
    @pytest.mark.parametrize(
        'hasher',
        (
            HasherChoice.blake2b,
            HasherChoice.blake2s,
            HasherChoice.blake3,
        ),
    )
    @pytest.mark.parametrize('separator', (':', b':'))
    def test_separator_can_be_changed(
        self,
        separator: typing.Union[str, bytes],
        hasher: HasherChoice,
    ) -> None:
        """Test that the separator can be changed."""
        signer = self.signer(separator=separator, hasher=hasher)

        signed = self.sign(signer, self.data)
        if isinstance(separator, self.signature_type):
            assert separator in signed
        elif isinstance(separator, bytes):
            assert separator.decode() in signed
        else:
            assert separator.encode() in signed

    @pytest.mark.xfail(
        not has_blake3(),
        reason='blake3 is not installed',
        raises=errors.MissingDependencyError,
    )
    @pytest.mark.parametrize(
        'hasher',
        (
            HasherChoice.blake2b,
            HasherChoice.blake2s,
            HasherChoice.blake3,
        ),
    )
    @pytest.mark.parametrize(
        ('encoder', 'regex'),
        (
            (B64URLEncoder, r'^[a-zA-Z0-9_\-]+(\.[a-zA-Z0-9_\-]+)?\.datadata$'),
            (B32Encoder, r'^[A-Z2-7]+(\.[A-Z2-7]+)?\.datadata$'),
            (HexEncoder, r'^[A-F0-9]+(\.[A-F0-9]+)?\.datadata$'),
        ),
    )
    def test_sign_unsign_with_encoder(
        self,
        encoder: typing.Type[EncoderInterface],
        regex: str,
        hasher: HasherChoice,
    ) -> None:
        """Test signing and unsigning using an encoder."""
        data = 'datadata' if self.signature_type is str else b'datadata'
        signer = self.signer(encoder=encoder, hasher=hasher)

        signed = self.sign(signer, data)
        assert re.match(
            regex,
            signed if self.signature_type is str else signed.decode(),
        ), signed

        unsigned = self.unsign(signer, signed)
        assert data == unsigned

    @pytest.mark.xfail(
        not has_blake3(),
        reason='blake3 is not installed',
        raises=errors.MissingDependencyError,
    )
    @pytest.mark.parametrize(
        'hasher',
        (
            HasherChoice.blake2b,
            HasherChoice.blake2s,
            HasherChoice.blake3,
        ),
    )
    def test_sign_unsign_parts_both_sig_containers(self, hasher: HasherChoice) -> None:
        """Test signing and unsigning in parts accepting both signature containers."""
        signer = self.signer(hasher=hasher)

        signature = self.sign_parts(signer, self.data)
        if self.signature_type is str:
            assert isinstance(signature, Blake2SignatureDump)
        else:
            assert isinstance(signature, Blake2Signature)

        if self.signature_type is str:
            other_signature = Blake2Signature(
                data=signature.data.encode(),
                signature=signature.signature.encode(),
            )
        else:
            other_signature = Blake2SignatureDump(
                data=signature.data.decode(),
                signature=signature.signature.decode(),
            )
        unsigned = self.unsign_parts(signer, other_signature)
        assert self.data == unsigned

    @pytest.mark.parametrize(
        'hasher',
        (
            HasherChoice.blake2b,
            HasherChoice.blake2s,
            HasherChoice.blake3,
        ),
    )
    def test_secret_too_short(self, hasher: HasherChoice) -> None:
        """Test secret too short."""
        with pytest.raises(
                errors.InvalidOptionError,
                match='1st secret should be longer than',
        ):
            self.signer(b's' * (self.signer_class.MIN_SECRET_SIZE - 1), hasher=hasher)

    @pytest.mark.parametrize(
        'hasher',
        (
            HasherChoice.blake2b,
            HasherChoice.blake2s,
            HasherChoice.blake3,
        ),
    )
    def test_secret_too_short_in_sequence(self, hasher: HasherChoice) -> None:
        """Test secret too short in a sequence."""
        with pytest.raises(
                errors.InvalidOptionError,
                match='1st secret should be longer than',
        ):
            self.signer([b's' * (self.signer_class.MIN_SECRET_SIZE - 1)], hasher=hasher)

        with pytest.raises(
                errors.InvalidOptionError,
                match='2nd secret should be longer than',
        ):
            self.signer(
                [self.secret, b's' * (self.signer_class.MIN_SECRET_SIZE - 1)],
                hasher=hasher,
            )

    @pytest.mark.parametrize(
        'hasher',
        (
            HasherChoice.blake2b,
            HasherChoice.blake2s,
            HasherChoice.blake3,
        ),
    )
    def test_digest_too_small(self, hasher: HasherChoice) -> None:
        """Test digest too small."""
        sizes = (
            -1,
            self.signer_class.MIN_DIGEST_SIZE - 1,
        )
        for digest_size in sizes:
            with pytest.raises(
                    errors.InvalidOptionError,
                    match='digest_size should be',
            ):
                self.signer(hasher=hasher, digest_size=digest_size)

    @pytest.mark.parametrize(
        'hasher',
        (
            HasherChoice.blake2b,
            HasherChoice.blake2s,
            # blake3 has no digest limit
        ),
    )
    def test_digest_too_large(self, hasher: HasherChoice) -> None:
        """Test digest too large."""
        digest_size = getattr(hashlib, hasher.value).MAX_DIGEST_SIZE + 1
        with pytest.raises(
                errors.InvalidOptionError,
                match='digest_size should be',
        ):
            self.signer(hasher=hasher, digest_size=digest_size)

    @pytest.mark.xfail(
        not has_blake3(),
        reason='blake3 is not installed',
        raises=errors.MissingDependencyError,
    )
    def test_blake3_no_digest_size_limit(self) -> None:
        """Test that BLAKE3 has no digest size limit."""
        signer = self.signer(
            self.secret,
            digest_size=1_000,
            hasher=self.signer_class.Hashers.blake3,
        )

        signed = self.sign(signer, self.data)
        assert len(signed) > 1_000
        assert self.data == self.unsign(signer, signed)

    @pytest.mark.xfail(
        not has_blake3(),
        reason='blake3 is not installed',
        raises=errors.MissingDependencyError,
    )
    @pytest.mark.parametrize(
        'hasher',
        (
            HasherChoice.blake2b,
            HasherChoice.blake2s,
            HasherChoice.blake3,
        ),
    )
    def test_unsign_no_separator(self, hasher: HasherChoice) -> None:
        """Test unsign with wrong data without separator."""
        signer = self.signer(hasher=hasher)

        with pytest.raises(errors.SignatureError, match='separator not found') as exc:
            self.unsign(signer, b'12345678')
        assert exc.value.__cause__ is None

    @pytest.mark.xfail(
        not has_blake3(),
        reason='blake3 is not installed',
        raises=errors.MissingDependencyError,
    )
    @pytest.mark.parametrize(
        'hasher',
        (
            HasherChoice.blake2b,
            HasherChoice.blake2s,
            HasherChoice.blake3,
        ),
    )
    def test_unsign_short_data_without_signature(self, hasher: HasherChoice) -> None:
        """Test unsign with very short data without signature."""
        signer = self.signer(hasher=hasher)

        with pytest.raises(
                errors.SignatureError,
                match='signature information is missing',
        ) as exc:
            self.unsign(
                signer,
                b'.',  # The shortest possible that passes the separator check
            )
        assert exc.value.__cause__ is None

        with pytest.raises(
                errors.SignatureError,
                match='signature information is missing',
        ) as exc:
            self.unsign(signer, b'.12345678')
        assert exc.value.__cause__ is None

    @pytest.mark.xfail(
        not has_blake3(),
        reason='blake3 is not installed',
        raises=errors.MissingDependencyError,
    )
    @pytest.mark.parametrize(
        'hasher',
        (
            HasherChoice.blake2b,
            HasherChoice.blake2s,
            HasherChoice.blake3,
        ),
    )
    def test_unsign_wrong_signature(self, hasher: HasherChoice) -> None:
        """Test unsign with wrong signed data."""
        signer = self.signer(hasher=hasher)

        with pytest.raises(
                errors.InvalidSignatureError,
                match='signature is not valid',
        ) as exc:
            self.unsign(signer, b's.')
        assert exc.value.__cause__ is None

        signed = self.sign(signer, self.data)

        with pytest.raises(
                errors.InvalidSignatureError,
                match='signature is not valid',
        ) as exc:
            self.unsign(signer, signed[1:])
        assert exc.value.__cause__ is None

        with pytest.raises(
                errors.InvalidSignatureError,
                match='signature is not valid',
        ) as exc:
            self.unsign(signer, signed[:-1])
        assert exc.value.__cause__ is None

    @pytest.mark.xfail(
        not has_blake3(),
        reason='blake3 is not installed',
        raises=errors.MissingDependencyError,
    )
    @pytest.mark.parametrize(
        'hasher',
        (
            HasherChoice.blake2b,
            HasherChoice.blake2s,
            HasherChoice.blake3,
        ),
    )
    @pytest.mark.parametrize(
        ('encoder', 'separator'),
        (
            (B64URLEncoder, b'A'),
            (B32Encoder, b'A'),
            (HexEncoder, b'A'),
        ),
    )
    def test_separator_in_encoder_alphabet(
        self,
        encoder: typing.Type[EncoderInterface],
        separator: bytes,
        hasher: HasherChoice,
    ) -> None:
        """Test error occurs when the separator is in the encoder alphabet."""
        with pytest.raises(
                errors.InvalidOptionError,
                match='separator character must not belong to the encoder',
        ):
            self.signer(separator=separator, encoder=encoder, hasher=hasher)

    @pytest.mark.xfail(
        not has_blake3(),
        reason='blake3 is not installed',
        raises=errors.MissingDependencyError,
    )
    @pytest.mark.parametrize(
        'hasher',
        (
            HasherChoice.blake2b,
            HasherChoice.blake2s,
            HasherChoice.blake3,
        ),
    )
    def test_separator_non_ascii(self, hasher: HasherChoice) -> None:
        """Test error occurs when the separator is non-ascii."""
        with pytest.raises(
                errors.InvalidOptionError,
                match='separator character must be ASCII',
        ):
            self.signer(separator=b'\x87', hasher=hasher)

    @pytest.mark.xfail(
        not has_blake3(),
        reason='blake3 is not installed',
        raises=errors.MissingDependencyError,
    )
    @pytest.mark.parametrize(
        'hasher',
        (
            HasherChoice.blake2b,
            HasherChoice.blake2s,
            HasherChoice.blake3,
        ),
    )
    def test_separator_empty(self, hasher: HasherChoice) -> None:
        """Test error occurs when the separator is empty."""
        with pytest.raises(
                errors.InvalidOptionError,
                match='the separator character must have a value',
        ):
            self.signer(separator=b'', hasher=hasher)

    @pytest.mark.xfail(
        not has_blake3(),
        reason='blake3 is not installed',
        raises=errors.MissingDependencyError,
    )
    @pytest.mark.parametrize(
        'hasher',
        (
            HasherChoice.blake2b,
            HasherChoice.blake2s,
            HasherChoice.blake3,
        ),
    )
    def test_custom_encoder_non_ascii_alphabet(self, hasher: HasherChoice) -> None:
        """Test encoder having a non-ASCII alphabet raises exception."""

        class Encoder(EncoderInterface):
            """Wrong encoder."""

            @property
            def alphabet(self) -> bytes:
                """Get encoder alphabet."""
                return b'\x87'

            def encode(self, data: typing.AnyStr) -> bytes:
                """Encode data."""
                pass  # pragma: nocover

            def decode(self, data: typing.AnyStr) -> bytes:
                """Decode data."""
                pass  # pragma: nocover

        with pytest.raises(
                errors.InvalidOptionError,
                match='encoder alphabet must be ASCII',
        ):
            self.signer(encoder=Encoder, hasher=hasher)

    @pytest.mark.xfail(
        not has_blake3(),
        reason='blake3 is not installed',
        raises=errors.MissingDependencyError,
    )
    @pytest.mark.parametrize(
        'hasher',
        (
            HasherChoice.blake2b,
            HasherChoice.blake2s,
            HasherChoice.blake3,
        ),
    )
    def test_custom_encoder_empty_alphabet(self, hasher: HasherChoice) -> None:
        """Test encoder having an empty alphabet raises exception."""

        class Encoder(EncoderInterface):
            """Wrong encoder."""

            @property
            def alphabet(self) -> bytes:
                """Get encoder alphabet."""
                return b''

            def encode(self, data: typing.AnyStr) -> bytes:
                """Encode data."""
                pass  # pragma: nocover

            def decode(self, data: typing.AnyStr) -> bytes:
                """Decode data."""
                pass  # pragma: nocover

        with pytest.raises(
                errors.InvalidOptionError,
                match='encoder alphabet must have a value',
        ):
            self.signer(encoder=Encoder, hasher=hasher)

    @pytest.mark.xfail(
        not has_blake3(),
        reason='blake3 is not installed',
        raises=errors.MissingDependencyError,
    )
    @pytest.mark.parametrize(
        'hasher',
        (
            HasherChoice.blake2b,
            HasherChoice.blake2s,
            HasherChoice.blake3,
        ),
    )
    def test_minimum_digest_size_can_be_changed(
        self,
        signer_min_digest_size_changed,
        hasher: HasherChoice,
    ) -> None:
        """Test that the min digest size limit can be changed."""
        signer = signer_min_digest_size_changed(
            self.secret,
            digest_size=8,
            hasher=hasher,
        )

        assert self.data == self.unsign(signer, self.sign(signer, self.data))

        with pytest.raises(
                errors.InvalidOptionError,
                match='digest_size should be',
        ):
            signer_min_digest_size_changed(
                self.secret,
                digest_size=signer_min_digest_size_changed.MIN_DIGEST_SIZE - 1,
                hasher=hasher,
            )

    @pytest.mark.xfail(
        not has_blake3(),
        reason='blake3 is not installed',
        raises=errors.MissingDependencyError,
    )
    @pytest.mark.parametrize(
        'hasher',
        (
            HasherChoice.blake2b,
            HasherChoice.blake2s,
            HasherChoice.blake3,
        ),
    )
    def test_minimum_secret_size_can_be_changed(
        self,
        signer_min_secret_size_changed,
        hasher: HasherChoice,
    ) -> None:
        """Test that the min secret size limit can be changed."""
        signer = signer_min_secret_size_changed(b'12345678', hasher=hasher)

        assert self.data == self.unsign(signer, self.sign(signer, self.data))

        with pytest.raises(
                errors.InvalidOptionError,
                match='secret should be longer than',
        ):
            signer_min_secret_size_changed(
                b's' * (signer_min_secret_size_changed.MIN_SECRET_SIZE - 1),
                hasher=hasher,
            )

    @pytest.mark.xfail(
        not has_blake3(),
        reason='blake3 is not installed',
        raises=errors.MissingDependencyError,
    )
    @pytest.mark.parametrize(
        'hasher',
        (
            HasherChoice.blake2b,
            HasherChoice.blake2s,
            HasherChoice.blake3,
        ),
    )
    @pytest.mark.parametrize(
        'secret',
        (
            'a string secret' * 3,
            b'a bytes secret' * 3,
            ['a list' * 3, 'string secret' * 3],
            [b'a list' * 3, b'bytes secret' * 3],
            ['a list' * 3, b'mixed secret' * 3],
            ('a tuple' * 3, 'secret' * 3),
        ),
    )
    def test_secret_can_be_any_sequence(
        self,
        secret: typing.Union[Secret, typing.Sequence[Secret]],
        hasher: HasherChoice,
    ) -> None:
        """Test that the min digest size limit can be changed."""
        signer = self.signer(secret, hasher=hasher)
        assert self.data == self.unsign(signer, self.sign(signer, self.data))

    @abstractmethod
    def test_versions_compat(
        self,
        version: str,
        hasher: HasherChoice,
        signed: str,
        compat: bool,
    ) -> None:
        """Test if previous versions' signed data is compatible with the current one."""
        signer: Signer = self.signer(b'too many secrets!', hasher=hasher)
        data: bytes = b'is compat ensured?'

        assert version_parse(version) >= version_parse('1.2.1')

        if compat:
            unsigned = self.unsign(signer, signed)

            if self.signature_type is bytes:
                assert data == unsigned
            else:
                assert data.decode() == unsigned
        else:
            with pytest.raises(errors.SignedDataError):
                self.unsign(signer, signed)
