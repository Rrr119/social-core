"""Configurable enterprise OpenID Connect backend.

The provider-specific issuer and endpoints are loaded from OIDC discovery.
Configure ``SOCIAL_AUTH_ENTERPRISE_OIDC_ENDPOINT`` with the issuer URL, for
example ``https://login.example.com/tenant``.
"""

from __future__ import annotations

from social_core.backends.base import ResponseT_co
from social_core.backends.open_id_connect import OpenIdConnectAuth
from social_core.exceptions import AuthConfigurationError, ErrorStage


class EnterpriseOpenIdConnect(OpenIdConnectAuth[ResponseT_co]):
    """Enterprise OpenID Connect backend with refresh-token support."""

    name = "enterprise"
    title = "Enterprise IdP"
    OIDC_ENDPOINT = ""
    DEFAULT_SCOPE = ["openid", "profile", "email", "offline_access"]
    DEFAULT_USE_PKCE = True
    EXTRA_DATA = [
        *(OpenIdConnectAuth.EXTRA_DATA or []),
        ("expires_in", "expires_in"),
    ]

    def _validated_endpoint(self, *, stage: ErrorStage = "begin") -> str:
        endpoint = self.oidc_endpoint()
        if not isinstance(endpoint, str) or not endpoint.strip():
            raise AuthConfigurationError(
                self,
                code="missing_setting",
                parameter="OIDC_ENDPOINT",
                stage=stage,
            )
        return endpoint

    def oidc_endpoint(self) -> str:
        endpoint = super().oidc_endpoint()
        return endpoint.rstrip("/") if isinstance(endpoint, str) else ""

    def oidc_config_url(self) -> str:
        self._validated_endpoint(stage="begin")
        return super().oidc_config_url()

    def authorization_url(self) -> str:
        self._validated_endpoint(stage="begin")
        return super().authorization_url()

    def access_token_url(self) -> str:
        self._validated_endpoint(stage="token_exchange")
        return super().access_token_url()

    def revoke_token_url(self, token, uid) -> str:
        self._validated_endpoint(stage="disconnect")
        return super().revoke_token_url(token, uid)

    def id_token_issuer(self) -> str:
        self._validated_endpoint(stage="token_validation")
        return super().id_token_issuer()

    def userinfo_url(self) -> str:
        self._validated_endpoint(stage="user_info")
        return super().userinfo_url()

    def jwks_uri(self) -> str:
        self._validated_endpoint(stage="token_validation")
        return super().jwks_uri()


EnterpriseOpenIdConnectAuth = EnterpriseOpenIdConnect
