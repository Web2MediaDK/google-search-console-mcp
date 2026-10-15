"""Encrypted storage for each user's Google Search Console refresh token."""

from __future__ import annotations

import hashlib
import json
import os
from typing import Protocol

from cryptography.fernet import Fernet, InvalidToken


class GoogleTokenStore(Protocol):
    def save(self, email: str, refresh_token: str) -> None: ...
    def get(self, email: str) -> str | None: ...
    def delete(self, email: str) -> None: ...


class FirestoreGoogleTokenStore:
    """Store encrypted refresh tokens in Firestore, keyed by a hash of email.

    ``GSC_TOKEN_ENCRYPTION_KEY`` must be a Fernet key stored in Secret Manager
    and exposed to the Cloud Run revision as an environment secret.
    """

    def __init__(self, *, project: str | None = None, collection: str = "gsc_user_tokens", client=None, key: str | None = None):
        raw_key = key or os.environ.get("GSC_TOKEN_ENCRYPTION_KEY")
        if not raw_key:
            raise RuntimeError("GSC_TOKEN_ENCRYPTION_KEY is required for hosted authentication")
        try:
            self._cipher = Fernet(raw_key.encode("ascii"))
        except (ValueError, TypeError) as exc:
            raise RuntimeError("GSC_TOKEN_ENCRYPTION_KEY must be a valid Fernet key") from exc

        if client is None:
            from google.cloud import firestore

            client = firestore.Client(project=project)
        self._client = client
        self._collection = client.collection(collection)
        self._state_collection_prefix = "gsc_oauth_"

    @staticmethod
    def _document_id(value: str) -> str:
        # OAuth state, codes, and bearer tokens are case-sensitive. Email callers
        # normalize explicitly; the generic document-key helper must not lowercase.
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def save(self, email: str, refresh_token: str) -> None:
        if not email or not refresh_token:
            raise ValueError("Email and refresh token are required")
        encrypted = self._cipher.encrypt(refresh_token.encode("utf-8")).decode("ascii")
        self._collection.document(self._document_id(email.strip().lower())).set(
            {"google_refresh_token_encrypted": encrypted}
        )

    def get(self, email: str) -> str | None:
        snapshot = self._collection.document(self._document_id(email.strip().lower())).get()
        if not snapshot.exists:
            return None
        encrypted = snapshot.to_dict().get("google_refresh_token_encrypted")
        if not encrypted:
            return None
        try:
            return self._cipher.decrypt(encrypted.encode("ascii")).decode("utf-8")
        except (InvalidToken, UnicodeDecodeError) as exc:
            raise RuntimeError("Stored Google token could not be decrypted") from exc

    def delete(self, email: str) -> None:
        self._collection.document(self._document_id(email.strip().lower())).delete()

    def put_state(self, collection: str, key: str, value: dict) -> None:
        """Persist encrypted MCP OAuth state, including DCR clients and tokens."""
        if not collection.replace("_", "").isalnum():
            raise ValueError("Invalid OAuth state collection name")
        ref = self._client.collection(self._state_collection_prefix + collection).document(
            self._document_id(key)
        )
        ciphertext = self._cipher.encrypt(json.dumps(value, separators=(",", ":")).encode())
        ref.set({"encrypted_state": ciphertext.decode("ascii")})

    def get_state(self, collection: str, key: str) -> dict | None:
        ref = self._client.collection(self._state_collection_prefix + collection).document(
            self._document_id(key)
        )
        snapshot = ref.get()
        if not snapshot.exists:
            return None
        ciphertext = snapshot.to_dict().get("encrypted_state")
        if not ciphertext:
            return None
        try:
            return json.loads(self._cipher.decrypt(ciphertext.encode("ascii")))
        except (InvalidToken, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("Stored OAuth state could not be decrypted") from exc

    def pop_state(self, collection: str, key: str) -> dict | None:
        """Read and delete one-time state in a Firestore transaction."""
        from google.cloud import firestore

        ref = self._client.collection(self._state_collection_prefix + collection).document(
            self._document_id(key)
        )
        transaction = self._client.transaction()

        @firestore.transactional
        def _consume(transaction):
            snapshot = ref.get(transaction=transaction)
            if not snapshot.exists:
                return None
            ciphertext = snapshot.to_dict().get("encrypted_state")
            transaction.delete(ref)
            if not ciphertext:
                return None
            try:
                return json.loads(self._cipher.decrypt(ciphertext.encode("ascii")))
            except (InvalidToken, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RuntimeError("Stored OAuth state could not be decrypted") from exc

        return _consume(transaction)

    def delete_state(self, collection: str, key: str) -> None:
        self._client.collection(self._state_collection_prefix + collection).document(
            self._document_id(key)
        ).delete()


class InMemoryGoogleTokenStore:
    """Small test double; never use this store in a deployed service."""

    def __init__(self):
        self._tokens: dict[str, str] = {}

    def save(self, email: str, refresh_token: str) -> None:
        self._tokens[email.strip().lower()] = refresh_token

    def get(self, email: str) -> str | None:
        return self._tokens.get(email.strip().lower())

    def delete(self, email: str) -> None:
        self._tokens.pop(email.strip().lower(), None)
