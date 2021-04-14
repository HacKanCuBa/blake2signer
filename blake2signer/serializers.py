"""Serializers: classes that implement the SerializerInterface."""

import json
import typing

from .interfaces import SerializerInterface


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
