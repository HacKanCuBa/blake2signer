"""Serializers: classes that implement the SerializerInterface."""

import json
import typing

from .interfaces import SerializerInterface
from .utils import force_bytes


class JSONSerializer(SerializerInterface):
    """JSON serializer."""

    def serialize(self, data: typing.Any, **kwargs: typing.Any) -> bytes:
        """Serialize given data to JSON."""
        return json.dumps(
            data,
            separators=(',', ':'),  # Use JSON compact encoding
            **kwargs,
        ).encode()

    def unserialize(self, data: bytes, **kwargs: typing.Any) -> typing.Any:
        """Unserialize given JSON data."""
        return json.loads(data, **kwargs)


class NullSerializer(SerializerInterface):
    """Null serializer that doesn't serializes anything."""

    def serialize(self, data: typing.Any, **kwargs: typing.Any) -> bytes:
        """Null serialize data (it just converts it to bytes)."""
        return force_bytes(data)

    def unserialize(self, data: bytes, **kwargs: typing.Any) -> typing.Any:
        """Return given data as-is."""
        return data
