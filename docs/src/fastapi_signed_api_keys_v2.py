"""Implementing signed API keys with FastAPI.

Do note that this example may break in the future due to FastAPI still being unstable.
Please file an issue if that happens: https://gitlab.com/hackancuba/blake2signer/-/issues.

Requirements:
    - Python 3.8+
    - fastapi[all]>=0.111.0
    - blake2signer>=2.0.0

Run:
    python3 <filename>.py
"""

import functools
import logging
import typing as t
from datetime import timedelta
from enum import Enum
from pathlib import Path
from secrets import token_bytes

import fastapi
import pydantic
from fastapi.security import APIKeyHeader
from fastapi_cli.cli import dev as fastapi_cli
from packaging.version import Version
from pydantic_settings import BaseSettings
from pydantic_settings import SettingsConfigDict

from blake2signer import Blake2TimestampSigner
from blake2signer.errors import ExpiredSignatureError
from blake2signer.errors import SignatureError
from blake2signer.utils import b64decode
from blake2signer.utils import b64encode

assert Version(fastapi.__version__) >= Version('0.111.0')

ENV_FILE = Path('.env')

logging.basicConfig(level=logging.INFO, style='{', format='{levelname}:     [{name}] {message}')
LOGGER = logging.getLogger('app')

API_KEY_LIFETIME = timedelta(minutes=5)  # Play around with this to see api key expired errors
API_KEY_PREFIX_SEPARATOR = '.'
API_KEY_SCOPE_SEPARATOR = '.'

ApiKeyT: t.TypeAlias = str
ApiKeyTokenT: t.TypeAlias = str
api_key_header = APIKeyHeader(name='x-api-key')


class AuthScopes(str, Enum):
    """Authentication scopes."""
    profile = 'profile'
    settings = 'settings'


AUTH_SCOPES = tuple(sorted(AuthScopes))
AUTH_SCOPES_TO_ID = {
    scope: idx
    for idx, scope in enumerate(AUTH_SCOPES)
}


class ApiKey(t.NamedTuple):
    """Api key and token pair."""
    key: ApiKeyT
    scope: AuthScopes
    token: ApiKeyTokenT


class Settings(BaseSettings):
    """Application settings."""
    model_config = SettingsConfigDict(env_file=ENV_FILE)

    secret: str


class GenericResponse(pydantic.BaseModel):
    """Generic response."""
    api_key: ApiKeyT
    scope: AuthScopes
    token: ApiKeyTokenT
    description: str


class GenericErrorResponse(pydantic.BaseModel):
    """Generic error response."""
    details: str


class ApiKeyError(Exception):
    """Generic API key error."""


class MissingScopeError(ApiKeyError):
    """The API key has no scope."""


class InvalidScopeError(ApiKeyError):
    """The API key scope is not valid."""

    def __init__(self, *args: t.Any, scope: t.Optional[AuthScopes]) -> None:
        super().__init__(*args)

        self.scope = scope


@functools.lru_cache(maxsize=None)
def get_settings() -> Settings:
    """Get application settings."""
    return Settings()  # type: ignore[call-arg]


def validate_api_key(
    scopes: fastapi.security.SecurityScopes,
    api_key: str = fastapi.Security(api_key_header),
    settings: Settings = fastapi.Depends(get_settings),
) -> ApiKey:
    """Return a validated API key obtained from the HTTP header.

    Returns:
        An API key.

    Raises:
        HTTPException: Invalid API key.
    """
    signer = get_api_keys_signer(settings.secret)
    scope = AuthScopes(scopes.scopes[0])

    try:
        token = verify_api_key(
            api_key,
            scope=scope,
            signer=signer,
            ttl=API_KEY_LIFETIME,
        )
    except InvalidScopeError as exc:
        detail = 'This API key is meant to be used for another scope'
        if exc.scope:
            detail += f': {exc.scope}'

        raise fastapi.HTTPException(
            status_code=fastapi.status.HTTP_401_UNAUTHORIZED,
            detail=detail,
        ) from exc
    except ExpiredSignatureError as exc:
        since = (exc.timestamp + API_KEY_LIFETIME).astimezone()

        raise fastapi.HTTPException(
            status_code=fastapi.status.HTTP_401_UNAUTHORIZED,
            detail=f'This API key is valid, but is expired since {since}',
        ) from exc
    except SignatureError as exc:
        raise fastapi.HTTPException(
            status_code=fastapi.status.HTTP_403_FORBIDDEN,
            detail='This API key is improper',
        ) from exc
    except MissingScopeError as exc:
        raise fastapi.HTTPException(
            status_code=fastapi.status.HTTP_403_FORBIDDEN,
            detail='This API key has no scope',
        ) from exc

    return ApiKey(api_key, scope, token)


@functools.lru_cache(maxsize=None)
def get_api_keys_signer(secret: str) -> Blake2TimestampSigner:
    """Get the corresponding signer."""
    signer = Blake2TimestampSigner(
        secret,
        personalisation=b'api keys',
        deterministic=True,
        separator=API_KEY_PREFIX_SEPARATOR,
    )

    return signer


def verify_api_key(
    key: str,
    *,
    scope: AuthScopes,
    signer: Blake2TimestampSigner,
    ttl: timedelta,
) -> ApiKeyTokenT:
    """Verify a given API key."""
    try:
        key_prefix, key = key.split(API_KEY_PREFIX_SEPARATOR, maxsplit=1)
    except ValueError as exc:
        raise MissingScopeError('This key has no scope in it') from exc

    # Remember that prefixes are not signed and can be anything! This is more a UX helper
    # for the user than a security feature.
    if key_prefix != scope:
        try:
            key_scope = AuthScopes(key_prefix)
        except ValueError:
            key_scope = None

        raise InvalidScopeError('This key is not valid for this scope', scope=key_scope)

    scoped_token = b64decode(signer.unsign(key, max_age=ttl))
    key_scope_id, token = scoped_token.split(API_KEY_SCOPE_SEPARATOR.encode())
    key_scope = get_scope_from_id(key_scope_id)

    # This is the actual, signed scope
    if key_scope != scope:
        raise InvalidScopeError(
            'This key is not valid for this scope',
            scope=AuthScopes(key_scope),
        )

    return ApiKeyTokenT(token.decode())


def generate_api_key(*, scope: AuthScopes, secret: str) -> ApiKey:
    """Generate a prefixed API key by signing a random token."""
    signer = get_api_keys_signer(secret)

    # Note that this is too simple for a real use-case, so you may prefer to associate the
    # token to the user, and use Blake2SerializerSigner to work with properly structured data.
    token = b64encode(token_bytes(16))
    signed_key = signer.sign(
        b64encode(get_scope_id(scope) + API_KEY_SCOPE_SEPARATOR.encode() + token),
    )

    return ApiKey(
        f'{scope}{API_KEY_PREFIX_SEPARATOR}{signed_key.decode()}',
        scope,
        token.decode(),
    )


def get_scope_id(scope: AuthScopes, /) -> bytes:
    """Get a short ID representing the scope."""
    return AUTH_SCOPES_TO_ID[scope].to_bytes(length=1, byteorder='big')


def get_scope_from_id(id_: bytes, /) -> AuthScopes:
    """Get the corresponding scope from a short ID."""
    return AUTH_SCOPES[int.from_bytes(id_, byteorder='big')]


def generate_and_save_secret() -> None:
    """Generate a new secret and store it in the env file."""
    # Note: this is mostly a toy function, you wouldn't use it like this in production, but
    # otherwise you would use a secret manager to store the secret and create the env file
    # or somehow populate the environment.
    # However, it is useful to illustrate this functionality.
    env_path = Path(ENV_FILE)
    env_path.touch()

    contents = []
    idx: t.Optional[int] = None
    with env_path.open(encoding='utf8') as env_file:
        for line_num, line in enumerate(env_file):
            contents.append(line)

            if line.startswith('SECRET='):
                secret = line.strip().removeprefix('SECRET="').removesuffix('"')
                if secret:
                    LOGGER.info('Secret already set, nothing to do: %s', secret)
                    return

                idx = line_num

    secret = generate_secret()
    line = f'SECRET="{secret}"\n'
    if idx is None:
        contents.append(line)
    else:
        contents[idx] = line

    with env_path.open('w', encoding='utf8') as env_file:
        env_file.writelines(contents)

    LOGGER.info('Secret saved in .env file: %s', secret)


def generate_secret() -> str:
    """Generate a secure, pseudo-random value for use as a secret."""
    return b64encode(token_bytes(64)).decode()


app = fastapi.FastAPI(
    debug=True,
    title='FastAPI+Blake2Signer',
    description='Sample FastAPI application that uses Blake2Signer to sign API keys.',
)


@app.get('/generate')
def generate(
    scope: AuthScopes = fastapi.Query(...),
    settings: Settings = fastapi.Depends(get_settings),
) -> GenericResponse:
    """Get a new API key with given scope."""
    key, scope, token = generate_api_key(scope=scope, secret=settings.secret)

    return GenericResponse(
        api_key=key,
        scope=scope,
        token=token,
        description='Here is your new API key',
    )


@app.get(
    '/profile',
    responses={
        fastapi.status.HTTP_401_UNAUTHORIZED: {
            'description': 'Invalid API key',
            'model': GenericErrorResponse,
        },
        fastapi.status.HTTP_403_FORBIDDEN: {
            'description': 'Missing or improper API key',
            'model': GenericErrorResponse,
        },
    },
)
def user_profile(
    api_key: ApiKey = fastapi.Security(validate_api_key, scopes=[AuthScopes.profile]),
) -> GenericResponse:
    """Get user profile.

    This is a sample endpoint that requires API key authentication with the "profile" scope.

    Returns:
        A generic response containing API key info.
    """
    key, scope, token = api_key

    return GenericResponse(
        api_key=key,
        scope=scope,
        token=token,
        description='This endpoint would show you your profile',
    )


@app.get(
    '/settings',
    responses={
        fastapi.status.HTTP_401_UNAUTHORIZED: {
            'description': 'Invalid API key',
            'model': GenericErrorResponse,
        },
        fastapi.status.HTTP_403_FORBIDDEN: {
            'description': 'Missing or improper API key',
            'model': GenericErrorResponse,
        },
    },
)
def user_settings(
    api_key: ApiKey = fastapi.Security(validate_api_key, scopes=[AuthScopes.settings]),
) -> GenericResponse:
    """Get user settings.

    This is a sample endpoint that requires API key authentication with the "settings" scope.

    Returns:
        A generic response containing API key info.
    """
    key, scope, token = api_key

    return GenericResponse(
        api_key=key,
        scope=scope,
        token=token,
        description='This endpoint would show you your settings',
    )


if __name__ == '__main__':
    generate_and_save_secret()

    fastapi_cli(Path(__file__))
