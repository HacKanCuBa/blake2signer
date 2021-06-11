"""Serializer signers tests."""

import io
import json
import typing
import zlib
from datetime import timedelta
from secrets import token_bytes
from time import time
from unittest import mock

import pytest

from .bases import BaseTests
from .bases import Signature
from .bases import Signer
from .test_timestampsigner import TimestampSignerTestsBase
from .. import errors
from ..compressors import GzipCompressor
from ..compressors import ZlibCompressor
from ..encoders import B32Encoder
from ..encoders import B64URLEncoder
from ..encoders import HexEncoder
from ..interfaces import CompressorInterface
from ..interfaces import EncoderInterface
from ..serializers import JSONSerializer
from ..serializers import NullSerializer
from ..signers import Blake2SerializerSigner


class SerializerSignerTestsBase(BaseTests):
    """Base to test a serializer signer."""

    data_compressible = 'datadata' * 100  # so compression is meaningful
    data_incompressible = token_bytes(10).hex()  # so it can't be compressed

    @property
    def signer_class(self) -> typing.Type[Signer]:
        """Get the signer class to test."""
        return Blake2SerializerSigner

    @property
    def signature_type(self) -> typing.Type[typing.Union[str, bytes]]:
        """Get the signature type for the signer (`str`)."""
        return str

    def sign(
        self,
        signer: Signer,
        data: typing.Any,
        **kwargs: typing.Any,
    ) -> typing.AnyStr:
        """Sign data with the signer."""
        return signer.dumps(data, **kwargs)

    def unsign(
        self,
        signer: Signer,
        signed_data: typing.Union[str, bytes],
        **kwargs: typing.Any,
    ) -> typing.Any:
        """Unsign signed data with the signer."""
        return signer.loads(signed_data)

    def sign_parts(
        self,
        signer: Signer,
        data: typing.Any,
        **kwargs: typing.Any,
    ) -> Signature:
        """Sign data with the signer in parts."""
        return signer.dumps_parts(data, **kwargs)

    def unsign_parts(
        self,
        signer: Signer,
        signature: Signature,
        **kwargs: typing.Any,
    ) -> typing.Any:
        """Unsign signature with the signer."""
        return signer.loads_parts(signature)

    @pytest.mark.parametrize(
        'data',
        (
            None,
            True,
            'datadata',
            [1, 2, 3],
            {
                'user': 'hackan',
            },
            [],
            {},
        ),
    )
    def test_dumps_loads_default(self, data: typing.Any) -> None:
        """Test dumping and loading with defaults is correct."""
        signer = self.signer()

        signed = self.sign(signer, data)
        assert isinstance(signed, str)

        unsigned = self.unsign(signer, signed)
        assert data == unsigned

    @pytest.mark.parametrize(
        ('encoder', 'regex'),
        (
            (B64URLEncoder, r'^[a-zA-Z0-9_\-]+(\.[a-zA-Z0-9_\-]+)?\.[a-zA-Z0-9_\-]+$'),
            (B32Encoder, r'^[A-Z2-7]+(\.[A-Z2-7]+)?\.[A-Z2-7]+$'),
            (HexEncoder, r'^[A-F0-9]+(\.[A-F0-9]+)?\.[A-F0-9]+$'),
        ),
    )
    def test_sign_unsign_with_encoder(
        self,
        encoder: typing.Type[EncoderInterface],
        regex: str,
    ) -> None:
        """Test signing and unsigning using an encoder."""
        super().test_sign_unsign_with_encoder(encoder, regex)

    def test_dumps_loads_compression_level_default(self) -> None:
        """Test dumping and loading with default compression level is correct."""
        signer = self.signer()

        signed = self.sign(signer, self.data_compressible, compress=False)
        signed_compressed = self.sign(
            signer,
            self.data_compressible,
            compress=True,
            compression_level=None,
        )
        assert len(signed_compressed) < len(signed)

        assert self.data_compressible == self.unsign(signer, signed_compressed)

    def test_dumps_loads_compression_level(self) -> None:
        """Test dumping and loading changing compression level is correct."""
        signer = self.signer()

        signed = self.sign(signer, self.data_compressible, compress=False)
        signed_compressed1 = self.sign(
            signer,
            self.data_compressible,
            compress=True,
            compression_level=1,
        )
        signed_compressed2 = self.sign(
            signer,
            self.data_compressible,
            compress=True,
            compression_level=9,
        )
        assert len(signed_compressed2) < len(signed_compressed1) < len(signed)

        assert self.data_compressible == self.unsign(signer, signed_compressed1)
        assert self.data_compressible == self.unsign(signer, signed_compressed2)

    def test_dumps_loads_auto_compression_incompressible(self) -> None:
        """Test dumping and loading with auto compression is correct."""
        signer = self.signer()

        signed = self.sign(signer, self.data_incompressible, compress=False)
        signed_not_compressed = self.sign(
            signer,
            self.data_incompressible,
            compress=True,
        )
        assert len(signed_not_compressed) == len(signed)

    def test_dumps_loads_force_compression(self) -> None:
        """Test dumping and loading forcing compression is correct."""
        signer = self.signer()

        signed = self.sign(signer, self.data_compressible, compress=False)
        signed_compressed = self.sign(
            signer,
            self.data_compressible,
            force_compression=True,
        )
        assert len(signed_compressed) < len(signed)

        assert self.data_compressible == self.unsign(signer, signed_compressed)

    def test_dumps_force_compression_bypasses_compress(self) -> None:
        """Test dumping and loading forcing compression bypasses compress."""
        signer = self.signer()

        signed = self.sign(signer, self.data_compressible, compress=False)
        signed_compressed = self.sign(
            signer,
            self.data_compressible,
            compress=False,
            force_compression=True,
        )
        assert len(signed_compressed) < len(signed)

    def test_dumps_force_compression_bypasses_compress_detrimental(self) -> None:
        """Test dumps forcing compression bypasses compress and is detrimental."""
        signer = self.signer()

        signed = self.sign(signer, self.data_incompressible, compress=False)
        signed_compressed = self.sign(
            signer,
            self.data_incompressible,
            compress=False,
            force_compression=True,
        )
        assert len(signed_compressed) > len(signed)

    def test_sign_unsign_with_different_serializer(self) -> None:
        """Test signing and unsigning using different serializer fails correctly."""
        signer1 = self.signer(serializer=JSONSerializer)
        signer2 = self.signer(serializer=NullSerializer)

        self.mix_signers_sign_unsign(signer1, signer2)

    def test_sign_unsign_with_different_compressor(self) -> None:
        """Test signing and unsigning using different compressor fails correctly."""
        signer1 = self.signer(compressor=ZlibCompressor)
        signer2 = self.signer(compressor=GzipCompressor)

        self.mix_signers_sign_unsign(signer1, signer2)

    def test_dumps_loads_with_custom_serializer(self) -> None:  # noqa: C901
        """Test dumping and loading using a custom serializer."""

        class Justice:
            """Some object."""

            def __init__(self, a: str = ''):
                self.a = a

        class CustomJSONEncoder(json.JSONEncoder):
            """Custom JSON encoder."""

            def default(self, o):
                """Encode object."""
                if isinstance(o, Justice):
                    return o.a

                return super().default(o)  # pragma: no cover

        class MyJSONSerializer(JSONSerializer):
            """Custom JSON serializer."""

            def serialize(self, data: typing.Any, **kwargs: typing.Any) -> bytes:
                """Serialize self.data."""
                return super().serialize(data, cls=CustomJSONEncoder, **kwargs)

        obj = Justice('acab')
        signer = self.signer(serializer=MyJSONSerializer)

        unsigned = self.unsign(signer, self.sign(signer, obj))
        assert obj.a == unsigned

    @pytest.mark.parametrize('flag', ('!', b'!'))
    def test_compression_flag_can_be_changed(
        self,
        flag: typing.Union[str, bytes],
    ) -> None:
        """Test that the compression flag can be changed."""
        signer = self.signer(compression_flag=flag)

        if isinstance(flag, bytes):
            assert signer._compression_flag == flag
        else:
            assert signer._compression_flag == flag.encode()

        signed = self.sign(signer, self.data_compressible)
        if isinstance(flag, bytes):
            assert flag.decode() in signed
        else:
            assert flag in signed

        unsigned = signer._proper_unsign(signer._decompose(signed.encode()))
        if isinstance(flag, bytes):
            assert unsigned.startswith(flag)
        else:
            assert unsigned.startswith(flag.encode())

    def test_compression_can_not_be_bombed(self) -> None:
        """Test that a malicious input can't bomb the compression."""
        bomb_data = b'\x00' * 1048576
        bomb = zlib.compress(bomb_data)

        assert len(bomb) < len(bomb_data)

        signer = self.signer(serializer=NullSerializer, compressor=ZlibCompressor)

        payload = signer._compression_flag + bomb
        signed = self.sign(signer, payload, compress=False)
        # If the bomb worked, then when unsigning the payload would be decompressed
        # If it failed, then the payload would stay the same, which is what should
        # happen here
        unsigned = self.unsign(signer, signed)
        assert len(payload) == len(unsigned)

    def test_compression_ratio_can_be_changed(self) -> None:
        """Test that the compression ratio can be changed."""
        data = 'datadatadatadata'  # Only somewhat compressible
        signer1 = self.signer(compression_ratio=10)
        signer2 = self.signer(compression_ratio=20)

        signed1 = self.sign(signer1, data, compress=True)  # Compressed
        signed2 = self.sign(signer2, data, compress=True)  # Not compressed

        assert len(signed1) < len(signed2)

    @pytest.mark.parametrize(
        'compressor',
        (
            ZlibCompressor,
            GzipCompressor,
        ),
    )
    def test_dumps_loads_with_compressor(
        self,
        compressor: typing.Type[CompressorInterface],
    ) -> None:
        """Test dumping and loading using a compressor."""
        signer = self.signer(compressor=compressor)

        signed = self.sign(signer, self.data_compressible, compress=False)
        signed_compressed = self.sign(signer, self.data_compressible, compress=True)
        assert len(signed_compressed) < len(signed)

        unsigned = self.unsign(signer, signed_compressed)
        assert self.data_compressible == unsigned

    @pytest.mark.parametrize(
        'data',
        ('datadata', b'datadata'),
    )
    def test_dumps_loads_with_null_serializer(self, data: typing.AnyStr) -> None:
        """Test dumping and loading using the null serializer."""
        signer = self.signer(serializer=NullSerializer)

        signed = self.sign(signer, data)
        assert isinstance(signed, str)

        unsigned = self.unsign(signer, signed)
        assert isinstance(unsigned, bytes)
        if isinstance(data, bytes):
            assert data == unsigned
        else:
            assert data == unsigned.decode()

    @pytest.mark.parametrize(
        'file_class',
        (
            io.StringIO,
            io.BytesIO,
        ),
    )
    def test_dump_load_file(self, file_class: typing.Type[typing.IO]) -> None:
        """Test dumping and loading to/from a file."""
        file = file_class()
        signer = self.signer()

        signed = signer.dump(self.data, file)
        assert file.tell() == len(signed)

        assert self.data == self.unsign(signer, signed)

        file.seek(0)
        unsigned = signer.load(file)
        assert file.tell() == len(signed)
        assert self.data == unsigned

    @pytest.mark.parametrize(
        'file_class',
        (
            io.StringIO,
            io.BytesIO,
        ),
    )
    def test_dump_load_file_with_null_serializer(
        self,
        file_class: typing.Type[typing.IO],
    ) -> None:
        """Test dumping and loading to/from a file."""
        file = file_class()
        signer = self.signer(serializer=NullSerializer)
        data = self.data.encode()

        signed = signer.dump(data, file)
        assert file.tell() == len(signed)

        assert data == self.unsign(signer, signed)

        file.seek(0)
        unsigned = signer.load(file)
        assert file.tell() == len(signed)
        assert data == unsigned

    @pytest.mark.parametrize(
        ('file_class', 'initial_data'),
        (
            (io.StringIO, 'acab' * 5),
            (io.BytesIO, b'acab' * 5),
        ),
    )
    def test_dump_load_file_containing_data(
        self,
        file_class: typing.Type[typing.IO],
        initial_data: typing.Union[str, bytes],
    ) -> None:
        """Test dumping and loading to/from a file that contains data.

        This is important to verify that we are not changing the file cursor in
        any unpredictable way.
        """
        file = file_class()
        file.write(initial_data)
        initial_pos = file.tell()
        signer = self.signer()

        signed = signer.dump(self.data, file)
        assert file.tell() == (len(initial_data) + len(signed))

        file.seek(initial_pos)
        unsigned = signer.load(file)
        assert file.tell() == (len(initial_data) + len(signed))
        assert self.data == unsigned

    def test_dumps_serializer_kwargs(self) -> None:
        """Test dumping using serializer kwargs."""
        signer = self.signer(deterministic=True, serializer=JSONSerializer)
        data = self.data + '\x87'

        signed1 = self.sign(
            signer,
            data,
            serializer_kwargs={'ensure_ascii': True},
        )
        signed1_1 = self.sign(
            signer,
            data,
            serializer_kwargs={'ensure_ascii': True},
        )
        assert signed1 == signed1_1  # It is effectively deterministic

        signed2 = self.sign(
            signer,
            data,
            serializer_kwargs={'ensure_ascii': False},
        )
        assert signed1 != signed2  # Change due only to the serializer options

    def test_dump_serializer_kwargs(self) -> None:
        """Test dumping to file using serializer kwargs."""
        file1 = io.StringIO()
        file1_1 = io.StringIO()
        file2 = io.StringIO()
        signer = self.signer(deterministic=True, serializer=JSONSerializer)
        data = self.data + '\x87'

        signer.dump(
            data,
            file1,
            serializer_kwargs={'ensure_ascii': True},
        )
        signer.dump(
            data,
            file1_1,
            serializer_kwargs={'ensure_ascii': True},
        )
        file1.seek(0)
        file1_1.seek(0)
        assert file1.read() == file1_1.read()  # It is effectively deterministic

        signer.dump(
            data,
            file2,
            serializer_kwargs={'ensure_ascii': False},
        )
        file1.seek(0)
        file2.seek(0)
        assert file1.read() != file2.read()  # Change due only to the serializer options

    def test_dumps_unserializable_data(self) -> None:
        """Test dumps unserializable data fails correctly."""
        signer = self.signer(serializer=JSONSerializer)

        with pytest.raises(
                errors.SerializationError,
                match='data can not be serialized',
        ) as exc:
            self.sign(signer, self.data.encode())  # Any non JSON encodable type
        assert exc.value.__cause__ is not None

    def test_loads_wrong_data(self) -> None:
        """Test loads wrong data."""
        signer = self.signer()

        with pytest.raises(
                errors.ConversionError,
                match='value can not be converted to bytes',
        ) as exc:
            self.unsign(signer, 1.0)  # type: ignore
        assert exc.value.__cause__ is not None

    @mock.patch('blake2signer.utils.base64.urlsafe_b64decode')
    def test_loads_decode_error(self, mock_b64decode: mock.MagicMock) -> None:
        """Test loads wrong data causing decoding error."""
        mock_b64decode.side_effect = ValueError
        signer = self.signer(encoder=B64URLEncoder)

        signed = self.sign(signer, self.data)
        with pytest.raises(
                errors.DecodeError,
                match='data can not be decoded',
        ) as exc:
            self.unsign(signer, signed)
        assert isinstance(exc.value.__cause__, ValueError)

    @mock.patch('blake2signer.compressors.zlib.decompress')
    def test_loads_decompression_error(self, mock_decompress: mock.MagicMock) -> None:
        """Test loads wrong data causing decompression error."""
        mock_decompress.side_effect = zlib.error
        signer = self.signer(compressor=ZlibCompressor)

        signed = self.sign(signer, self.data_compressible, compress=True)
        with pytest.raises(
                errors.DecompressionError,
                match='data can not be decompressed',
        ) as exc:
            self.unsign(signer, signed)
        assert isinstance(exc.value.__cause__, zlib.error)

    @mock.patch('blake2signer.serializers.json.loads')
    def test_loads_unserialization_error(self, mock_json_loads: mock.MagicMock) -> None:
        """Test loads wrong data causing unserialization error."""
        mock_json_loads.side_effect = ValueError
        signer = self.signer(serializer=JSONSerializer)

        signed = self.sign(signer, self.data)
        with pytest.raises(
                errors.UnserializationError,
                match='data can not be unserialized',
        ) as exc:
            self.unsign(signer, signed)
        assert isinstance(exc.value.__cause__, ValueError)

    @mock.patch('blake2signer.compressors.zlib.compress')
    def test_dumps_compression_error(self, mock_zlib_compress: mock.MagicMock) -> None:
        """Test compression error while dumping."""
        mock_zlib_compress.side_effect = zlib.error

        signer = self.signer(compressor=ZlibCompressor)

        with pytest.raises(
                errors.CompressionError,
                match='data can not be compressed',
        ) as exc:
            self.sign(signer, self.data_compressible, compress=True)
        assert isinstance(exc.value.__cause__, zlib.error)

    @mock.patch('blake2signer.encoders.b64encode')
    def test_dumps_encoding_error(self, mock_b64encode: mock.MagicMock) -> None:
        """Test encoding error while dumping."""
        mock_b64encode.side_effect = ValueError

        signer = self.signer(encoder=B64URLEncoder)

        with pytest.raises(
                errors.EncodeError,
                match='data can not be encoded',
        ) as exc:
            self.sign(signer, self.data)
        assert isinstance(exc.value.__cause__, ValueError)

    def test_dumps_invalid_compression_level(self) -> None:
        """Test invalid compression level for dumps."""
        signer = self.signer(compressor=ZlibCompressor)

        with pytest.raises(
                errors.CompressionError,
                match='compression level must be between 1 and 9',
        ) as exc:
            self.sign(signer, self.data, compress=True, compression_level=10)
        assert exc.value.__cause__ is None

        with pytest.raises(
                errors.CompressionError,
                match='compression level must be between 1 and 9',
        ) as exc:
            # noinspection PyArgumentEqualDefault
            self.sign(signer, self.data, compress=True, compression_level=0)
        assert exc.value.__cause__ is None

    def test_compression_flag_non_ascii(self) -> None:
        """Test error occurs when the compression flag is non-ascii."""
        with pytest.raises(
                errors.InvalidOptionError,
                match='compression flag character must be ASCII',
        ):
            self.signer(compression_flag=b'\x87')

    def test_compression_flag_empty(self) -> None:
        """Test error occurs when the compression flag is empty."""
        with pytest.raises(
                errors.InvalidOptionError,
                match='the compression flag character must have a value',
        ):
            self.signer(compression_flag=b'')

    @pytest.mark.parametrize(
        ('encoder', 'flag'),
        (
            (B64URLEncoder, b'A'),
            (B32Encoder, b'A'),
            (HexEncoder, b'A'),
        ),
    )
    def test_compression_flag_in_encoder_alphabet(
        self,
        encoder: typing.Type[EncoderInterface],
        flag: bytes,
    ) -> None:
        """Test error occurs when the compression flag is in the encoder alphabet."""
        with pytest.raises(
                errors.InvalidOptionError,
                match='the compression flag character must not belong to the encoder',
        ):
            self.signer(compression_flag=flag, encoder=encoder)

    def test_compression_ratio_out_of_bounds(self) -> None:
        """Test error occurs when the compression ratio is out of bounds."""
        with pytest.raises(
                errors.InvalidOptionError,
                match='compression ratio must be',
        ):
            self.signer(compression_ratio=-1)

        with pytest.raises(
                errors.InvalidOptionError,
                match='compression ratio must be',
        ):
            self.signer(compression_ratio=100)

    def test_load_file_error(self) -> None:
        """Test error occurring during reading from a file."""
        file = mock.MagicMock()
        file.read.side_effect = TimeoutError
        signer = self.signer()

        with pytest.raises(
                errors.FileError,
                match='file can not be read',
        ):
            signer.load(file)

    def test_dump_file_error(self) -> None:
        """Test error occurring during writing to a file."""
        file = mock.MagicMock()
        file.write.side_effect = PermissionError
        signer = self.signer()

        with pytest.raises(
                errors.FileError,
                match='file can not be written',
        ):
            signer.dump(self.data, file)

    def test_dump_file_binary_conversion_error(self) -> None:
        """Test error occurring during _write when file is in binary mode."""
        file = io.BytesIO()
        signer = self.signer()

        with pytest.raises(
                errors.ConversionError,
                match='can not be converted to bytes',
        ):
            signer._write(file, '\uD83D')


class TestsBlake2SerializerSignerTimestamp(
        SerializerSignerTestsBase,
        TimestampSignerTestsBase,
):
    """Blake2SerializerSigner tests with timestamp."""

    def signer(
        self,
        secret: typing.Union[None, str, bytes] = None,
        **kwargs: typing.Any,
    ) -> Signer:
        """Get the signer to test."""
        kwargs.setdefault('max_age', 5)
        return super().signer(secret, **kwargs)

    @pytest.mark.parametrize(
        'max_age',
        (None, 2, 2.5, timedelta(hours=2)),
    )
    @mock.patch('blake2signer.bases.time')
    def test_max_age_can_be_changed(
        self,
        mock_time: mock.MagicMock,
        max_age: typing.Union[None, int, float, timedelta],
    ) -> None:
        """Test that max age can be changed correctly."""
        timestamp = int(time())
        mock_time.return_value = timestamp
        signer = self.signer(max_age=max_age)

        signed = self.sign(signer, self.data)
        assert self.data == self.unsign(signer, signed)

        if max_age:
            if isinstance(max_age, timedelta):
                mock_time.return_value += max_age.total_seconds()
            else:
                mock_time.return_value += max_age
            mock_time.return_value += 0.1  # It has to be a bit bigger than max_age

            with pytest.raises(
                    errors.ExpiredSignatureError,
                    match='signature has expired',
            ) as exc:
                self.unsign(signer, signed)
            assert exc.value.__cause__ is None
            assert exc.value.timestamp.timestamp() == timestamp


class TestsBlake2SerializerSigner(SerializerSignerTestsBase):
    """Blake2SerializerSigner tests (without timestamp)."""

    def test_sign_unsign_with_different_signer(self) -> None:
        """Test signing and unsigning using different signer fails correctly."""
        signer1 = self.signer(max_age=None)  # Regular signer
        signer2 = self.signer(max_age=5)  # Timestamp signer

        self.mix_signers_sign_unsign(signer1, signer2)
