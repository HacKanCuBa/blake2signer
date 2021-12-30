"""Serializers: classes that implement the SerializerInterface."""

import json
import typing

from .interfaces import SerializerInterface
from .utils import force_bytes


class JSONSerializer(SerializerInterface):
    """JSON serializer."""

    def serialize(self, data: typing.Any, **kwargs: typing.Any) -> bytes:
        """Serialize given data to JSON.

        Args:
            data: Data to serialize.

        Keyword Args:
            **kwargs: Additional arguments for `json.dumps`.

        Returns:
            Serialized data
        """
        kwargs.setdefault('separators', (',', ':'))  # Use JSON compact encoding
        return json.dumps(data, **kwargs).encode()

    def unserialize(self, data: bytes, **kwargs: typing.Any) -> typing.Any:
        """Unserialize given JSON data.

        Args:
            data: Serialized data to unserialize.

        Keyword Args:
            **kwargs: Additional arguments for `json.loads`.

        Returns:
            Original data.
        """
        return json.loads(data, **kwargs)


class NullSerializer(SerializerInterface):
    """Null serializer that doesn't serializes anything."""

    def serialize(self, data: typing.Any, **kwargs: typing.Any) -> bytes:
        """Null serialize data (it just converts it to bytes).

        Args:
            data: Data to serialize.

        Keyword Args:
            **kwargs: Ignored.

        Returns:
            Serialized data
        """
        return force_bytes(data)

    def unserialize(self, data: bytes, **kwargs: typing.Any) -> typing.Any:
        """Return given data as-is.

        Args:
            data: Serialized data to unserialize.

        Keyword Args:
            **kwargs: Ignored.

        Returns:
            Original data.
        """
        return data
