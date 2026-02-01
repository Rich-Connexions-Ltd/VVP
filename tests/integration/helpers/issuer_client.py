"""Issuer API client wrapper for integration tests."""

from typing import Any

import httpx


class IssuerClient:
    """Wrapper for issuer API calls in integration tests."""

    def __init__(self, base_url: str, api_key: str):
        """Initialize the issuer client.

        Args:
            base_url: Base URL of the issuer service (e.g., http://localhost:8001)
            api_key: API key for authentication
        """
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self._client: httpx.AsyncClient | None = None

    @property
    def client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers={"X-API-Key": self.api_key},
                timeout=30.0,
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def health_check(self) -> dict:
        """Check issuer service health."""
        response = await self.client.get("/healthz")
        response.raise_for_status()
        return response.json()

    async def create_identity(
        self,
        name: str,
        publish_to_witnesses: bool = False,
    ) -> dict:
        """Create a new issuer identity.

        Args:
            name: Unique name for the identity
            publish_to_witnesses: Whether to publish to witnesses

        Returns:
            Response containing identity details
        """
        response = await self.client.post(
            "/identity",
            json={
                "name": name,
                "publish_to_witnesses": publish_to_witnesses,
            },
        )
        response.raise_for_status()
        return response.json()

    async def get_identity(self, aid: str) -> dict:
        """Get identity by AID."""
        response = await self.client.get(f"/identity/{aid}")
        response.raise_for_status()
        return response.json()

    async def rotate_identity(
        self,
        aid: str,
        next_key_count: int | None = None,
        next_threshold: str | None = None,
        publish_to_witnesses: bool = False,
    ) -> dict:
        """Rotate keys for an identity.

        Args:
            aid: AID of the identity to rotate
            next_key_count: Number of next keys to generate
            next_threshold: Signing threshold for next keys
            publish_to_witnesses: Whether to publish rotation to witnesses

        Returns:
            Response containing rotation details
        """
        payload = {"publish_to_witnesses": publish_to_witnesses}
        if next_key_count is not None:
            payload["next_key_count"] = next_key_count
        if next_threshold is not None:
            payload["next_threshold"] = next_threshold

        response = await self.client.post(f"/identity/{aid}/rotate", json=payload)
        response.raise_for_status()
        return response.json()

    async def create_registry(
        self,
        name: str,
        identity_name: str,
    ) -> dict:
        """Create a credential registry.

        Args:
            name: Unique name for the registry
            identity_name: Name of the identity to associate with registry

        Returns:
            Response containing registry details
        """
        response = await self.client.post(
            "/registry",
            json={
                "name": name,
                "identity_name": identity_name,
            },
        )
        response.raise_for_status()
        return response.json()

    async def issue_credential(
        self,
        registry_name: str,
        schema_said: str,
        attributes: dict[str, Any],
        recipient_aid: str | None = None,
        edges: dict[str, Any] | None = None,
        rules: dict[str, Any] | None = None,
        private: bool = False,
        publish_to_witnesses: bool = False,
    ) -> dict:
        """Issue a new ACDC credential.

        Args:
            registry_name: Name of the registry to track this credential
            schema_said: SAID of the schema for this credential
            attributes: Credential attributes (the 'a' section)
            recipient_aid: Optional recipient AID for targeted credentials
            edges: Optional edges to other credentials
            rules: Optional rules section
            private: Whether to add privacy-preserving nonces
            publish_to_witnesses: Whether to publish TEL to witnesses

        Returns:
            Response containing credential SAID and details
        """
        payload = {
            "registry_name": registry_name,
            "schema_said": schema_said,
            "attributes": attributes,
            "private": private,
            "publish_to_witnesses": publish_to_witnesses,
        }
        if recipient_aid:
            payload["recipient_aid"] = recipient_aid
        if edges:
            payload["edges"] = edges
        if rules:
            payload["rules"] = rules

        response = await self.client.post("/credential/issue", json=payload)
        response.raise_for_status()
        return response.json()

    async def get_credential(self, said: str) -> dict:
        """Get credential by SAID."""
        response = await self.client.get(f"/credential/{said}")
        response.raise_for_status()
        return response.json()

    async def list_credentials(
        self,
        registry_name: str | None = None,
        status: str | None = None,
    ) -> list[dict]:
        """List credentials with optional filtering."""
        params = {}
        if registry_name:
            params["registry_name"] = registry_name
        if status:
            params["status"] = status

        response = await self.client.get("/credential", params=params)
        response.raise_for_status()
        return response.json()["credentials"]

    async def revoke_credential(
        self,
        said: str,
        reason: str | None = None,
        publish_to_witnesses: bool = False,
    ) -> dict:
        """Revoke a credential.

        Args:
            said: SAID of the credential to revoke
            reason: Optional revocation reason
            publish_to_witnesses: Whether to publish revocation to witnesses

        Returns:
            Response confirming revocation
        """
        payload = {"publish_to_witnesses": publish_to_witnesses}
        if reason:
            payload["reason"] = reason

        response = await self.client.post(f"/credential/{said}/revoke", json=payload)
        response.raise_for_status()
        return response.json()

    async def build_dossier(
        self,
        root_said: str,
        format: str = "json",
        include_tel: bool = True,
    ) -> bytes:
        """Build a dossier from a credential chain.

        Args:
            root_said: SAID of the root credential
            format: Output format ('json' or 'cesr')
            include_tel: Whether to include TEL events

        Returns:
            Dossier content as bytes
        """
        response = await self.client.post(
            "/dossier/build",
            json={
                "root_said": root_said,
                "format": format,
                "include_tel": include_tel,
            },
        )
        response.raise_for_status()
        return response.content

    async def build_aggregate_dossier(
        self,
        root_saids: list[str],
        format: str = "json",
        include_tel: bool = True,
    ) -> bytes:
        """Build an aggregate dossier from multiple root credentials.

        Args:
            root_saids: List of root credential SAIDs
            format: Output format ('json' or 'cesr')
            include_tel: Whether to include TEL events

        Returns:
            Dossier content as bytes
        """
        response = await self.client.post(
            "/dossier/build",
            json={
                "root_saids": root_saids,
                "format": format,
                "include_tel": include_tel,
            },
        )
        response.raise_for_status()
        return response.content

    async def get_dossier(
        self,
        said: str,
        format: str = "json",
        include_tel: bool = True,
    ) -> bytes:
        """Get dossier by credential SAID.

        Args:
            said: SAID of the credential
            format: Output format ('json' or 'cesr')
            include_tel: Whether to include TEL events

        Returns:
            Dossier content as bytes
        """
        params = {"format": format, "include_tel": str(include_tel).lower()}
        response = await self.client.get(f"/dossier/{said}", params=params)
        response.raise_for_status()
        return response.content
