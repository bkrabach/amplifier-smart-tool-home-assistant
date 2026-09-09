"""The approved Linux operating-system secret store required by C9.

C9: "The tool MUST store a credential only when a person explicitly requests it
by invoking `login`, and only into an approved OS secret store on Linux. If no
approved store is available, or a store operation fails, the operation MUST fail
explicitly and MUST NOT fall back to a file, an environment variable, a
plaintext store, or any other location."

Three rules follow from that, and this module holds all three:

* ``keyring`` is imported lazily, inside the first operation that actually needs
  a store, so metadata paths (``manifest``, ``--help``) and every offline and
  model path never import it or wake a backend;
* only an explicit allow-list of operating-system-provided stores is accepted -
  an absent, unapproved, ``null``, ``fail``, or plaintext-file backend is
  refused, and there is no fallback of any kind;
* a backend's own exception is never chained onto ours, because a backend may
  quote the value it was handed and an exception context outlives the
  ``except`` block.
"""

from __future__ import annotations

import sys
from collections.abc import Callable

SERVICE_NAME = "ha-analysis"

#: ``(module, class)`` identities of the operating-system stores this tool trusts.
APPROVED_BACKENDS: frozenset[tuple[str, str]] = frozenset(
    {
        ("keyring.backends.SecretService", "Keyring"),
        ("keyring.backends.libsecret", "Keyring"),
        ("keyring.backends.kwallet", "DBusKeyring"),
        ("keyring.backends.kwallet", "DBusKeyringKWallet4"),
    }
)
CHAINER_BACKEND: tuple[str, str] = ("keyring.backends.chainer", "ChainerBackend")
MAXIMUM_CHAIN_DEPTH = 8
MAXIMUM_KEY_LENGTH = 512
MAXIMUM_CREDENTIAL_LENGTH = 4096


class SecretStoreError(Exception):
    """Base class for every fail-closed secret-store condition."""

    code = "secret_store_failed"


class SecretStoreUnavailableError(SecretStoreError):
    """No approved operating-system secret store could be used."""

    code = "secret_store_unavailable"


class SecretStoreDependencyError(SecretStoreUnavailableError):
    """This tool's own ``keyring`` dependency is not installed.

    Distinct from :class:`SecretStoreUnavailableError` on purpose: "this
    installation is incomplete" and "this computer offers no approved secret
    store" call for different fixes, and collapsing them hides a packaging
    defect behind a plausible-looking environment message.
    """

    code = "secret_store_dependency_missing"


class UnsupportedPlatformError(SecretStoreUnavailableError):
    """v1 defines credential storage on Linux only; anything else is refused."""

    code = "unsupported_platform"


class SecretStoreOperationError(SecretStoreError):
    """An approved store was reached, but the requested operation failed."""

    code = "secret_store_operation_failed"


def backend_identity(backend: object) -> tuple[str, str]:
    """Return the ``(module, class)`` identity used for allow-list decisions."""

    kind = type(backend)
    return (kind.__module__, kind.__name__)


def approve_backend(backend: object, _depth: int = 0) -> tuple[str, str]:
    """Return an approved backend's identity, or fail closed.

    A chainer is approved only when it is non-empty and *every* member is itself
    approved, because a chainer may serve any single request from any member: a
    chain that holds one plaintext member is a plaintext store.
    """

    if _depth > MAXIMUM_CHAIN_DEPTH:
        raise SecretStoreUnavailableError("The keyring backend chain is too deep to approve.")
    identity = backend_identity(backend)
    if identity == CHAINER_BACKEND:
        try:
            members = list(getattr(backend, "backends", None) or ())
        except Exception as error:  # A backend must never decide by raising.
            raise SecretStoreUnavailableError(
                "The keyring backend chain could not be read."
            ) from error
        if not members:
            raise SecretStoreUnavailableError(
                "No approved operating-system secret store is available."
            )
        for member in members:
            approve_backend(member, _depth + 1)
        return identity
    if identity not in APPROVED_BACKENDS:
        raise SecretStoreUnavailableError(
            "The active keyring backend is not an approved operating-system secret store."
        )
    return identity


def describe_identity(identity: tuple[str, str]) -> str:
    """Render a non-secret backend identity for a management document."""

    return f"{identity[0]}.{identity[1]}"


def _default_backend_factory() -> object:
    try:
        import keyring  # Lazy on purpose: no metadata or offline path may import this.
    except ImportError as error:
        raise SecretStoreDependencyError(
            "The keyring package this tool requires for secret-store access is "
            "not installed in the running environment."
        ) from error
    return keyring.get_keyring()


class KeyringSecretStore:
    """Reach an approved operating-system secret store, or fail closed."""

    def __init__(
        self,
        *,
        backend_factory: Callable[[], object] | None = None,
        platform: str | None = None,
    ) -> None:
        self._backend_factory = backend_factory or _default_backend_factory
        self._platform = platform if platform is not None else sys.platform
        self._backend: object | None = None
        self._identity: tuple[str, str] | None = None

    def _resolve(self) -> object:
        if self._backend is not None:
            return self._backend
        if not self._platform.startswith("linux"):
            raise UnsupportedPlatformError(
                "This tool stores credentials on Linux only; no other platform is defined."
            )
        try:
            backend = self._backend_factory()
        except SecretStoreError:
            raise  # Already a precise, fail-closed diagnosis; do not blur it.
        except Exception as error:
            raise SecretStoreUnavailableError(
                "No operating-system secret store backend could be resolved."
            ) from error
        self._identity = approve_backend(backend)
        self._backend = backend
        return backend

    def describe(self) -> str:
        self._resolve()
        assert self._identity is not None
        return describe_identity(self._identity)

    def set_credential(self, key: str, credential: str) -> None:
        backend = self._resolve()
        _require_key(key)
        _require_storable_credential(credential)
        if not _attempt(lambda: backend.set_password(SERVICE_NAME, key, credential)):
            raise SecretStoreOperationError("The secret store rejected the write.")

    def get_credential(self, key: str) -> str | None:
        backend = self._resolve()
        _require_key(key)
        held: list[object] = []
        if not _attempt(lambda: held.append(backend.get_password(SERVICE_NAME, key))):
            raise SecretStoreOperationError("The secret store rejected the read.")
        value = held[0]
        if value is None:
            return None
        if not isinstance(value, str):
            raise SecretStoreOperationError("The secret store returned an unusable value.")
        return value

    def has_credential(self, key: str) -> bool:
        """Report presence without letting the value escape this call."""

        return self.get_credential(key) is not None

    def delete_credential(self, key: str) -> bool:
        backend = self._resolve()
        _require_key(key)
        if not self.has_credential(key):
            return False
        if not _attempt(lambda: backend.delete_password(SERVICE_NAME, key)):
            # A concurrent deletion is not a failure: the end state is correct.
            if not self.has_credential(key):
                return True
            raise SecretStoreOperationError("The secret store rejected the deletion.")
        return True


def _attempt(operation: Callable[[], object]) -> bool:
    """Run a backend call, reporting success as a bool and keeping no exception.

    ``raise ... from None`` would still leave the backend's exception reachable
    through ``__context__``, and that exception may quote the credential. Losing
    the reference entirely is the only way to be sure it cannot be read back.
    """

    try:
        operation()
    except Exception:
        return False
    return True


def _require_key(key: str) -> None:
    if not isinstance(key, str) or not key or len(key) > MAXIMUM_KEY_LENGTH:
        raise SecretStoreOperationError("The secret-store key is not usable.")


def _require_storable_credential(credential: str) -> None:
    if not isinstance(credential, str) or not credential:
        raise SecretStoreOperationError("A credential must be a non-empty string.")
    if len(credential) > MAXIMUM_CREDENTIAL_LENGTH:
        raise SecretStoreOperationError("The credential is longer than this tool accepts.")
