from __future__ import annotations

import json
from functools import partial
from urllib.parse import urlsplit

import responses

from social_core.backends.enterprise import EnterpriseOpenIdConnect
from social_core.exceptions import AuthConfigurationError
from social_core.utils import parse_qs

from .open_id_connect import OpenIdConnectTest

IDP_URL = "https://idp.example.com"
ISSUER = f"{IDP_URL}/tenant"
USERINFO_URL = f"{ISSUER}/userinfo"


class EnterpriseOpenIdConnectTest(OpenIdConnectTest[EnterpriseOpenIdConnect]):
    """Exercise the backend against a fully local mock enterprise IdP."""

    backend_path = "social_core.backends.enterprise.EnterpriseOpenIdConnect"
    issuer = ISSUER
    user_data_url = USERINFO_URL
    expected_username = "alice"
    openid_config_body = json.dumps(
        {
            "issuer": ISSUER,
            "authorization_endpoint": f"{ISSUER}/authorize",
            "token_endpoint": f"{ISSUER}/token",
            "userinfo_endpoint": USERINFO_URL,
            "revocation_endpoint": f"{ISSUER}/revoke",
            "jwks_uri": f"{ISSUER}/jwks",
            "response_types_supported": ["code"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
            ],
            "code_challenge_methods_supported": ["S256"],
        }
    )
    user_data_body = json.dumps(
        {
            "sub": "1234",
            "preferred_username": "alice",
            "name": "Alice Example",
            "given_name": "Alice",
            "family_name": "Example",
            "email": "alice@example.com",
        }
    )

    def extra_settings(self):
        return {
            **super().extra_settings(),
            f"SOCIAL_AUTH_{self.name}_OIDC_ENDPOINT": ISSUER,
        }

    def prepare_access_token_body(self, *args, **kwargs):
        body = json.loads(super().prepare_access_token_body(*args, **kwargs))
        body["expires_in"] = 3600
        body.setdefault("refresh_token", "initial-refresh-token")
        return json.dumps(body)

    def pre_complete_callback(self, start_url) -> None:
        responses.add(
            responses.GET,
            USERINFO_URL,
            status=200,
            body=self.user_data_body,
            content_type="application/json",
        )
        super().pre_complete_callback(start_url)

    def refresh_request_body(self):
        return parse_qs(responses.calls[-1].request.body)

    def test_login_against_mock_idp(self) -> None:
        user = self.do_login()
        social = user.social[0]

        self.assertEqual(social.uid, "1234")
        self.assertEqual(user.email, "alice@example.com")
        self.assertEqual(social.extra_data["refresh_token"], "initial-refresh-token")
        self.assertEqual(social.extra_data["expires_in"], 3600)
        hosts = {urlsplit(call.request.url).hostname for call in responses.calls}
        self.assertLessEqual(hosts, {"idp.example.com", "myapp.com", "testserver"})

    def test_partial_pipeline_preserves_validated_identity(self) -> None:
        user = self.do_partial_pipeline()
        self.assertEqual(user.social[0].uid, "1234")

    def test_refresh_token_rotation(self) -> None:
        social = self.login_for_refresh()
        refreshed_body = self.prepare_access_token_body(
            access_token="refreshed-access-token",  # ruff: ignore[hardcoded-password-func-arg]
            refresh_token="rotated-refresh-token",  # ruff: ignore[hardcoded-password-func-arg]
            include_nonce=False,
        )

        self.refresh_social(social, refreshed_body)

        self.assertEqual(social.extra_data["access_token"], "refreshed-access-token")
        self.assertEqual(social.extra_data["refresh_token"], "rotated-refresh-token")
        params = self.refresh_request_body()
        self.assertEqual(params["grant_type"], "refresh_token")
        self.assertEqual(params["refresh_token"], "refresh-token")
        self.assertEqual(params["client_id"], self.client_key)

    def test_expired_access_token_refreshes_automatically(self) -> None:
        social = self.login_for_refresh()
        social.extra_data["expires_on"] = 1
        responses.add(
            responses.POST,
            self.backend.refresh_token_url(),
            status=200,
            body=self.prepare_access_token_body(
                access_token="automatic-refreshed-token",  # ruff: ignore[hardcoded-password-func-arg]
                refresh_token="automatic-rotated-token",  # ruff: ignore[hardcoded-password-func-arg]
                include_nonce=False,
            ),
            content_type="application/json",
        )

        token = social.get_access_token(self.strategy)

        self.assertEqual(token, "automatic-refreshed-token")
        self.assertEqual(social.extra_data["refresh_token"], "automatic-rotated-token")

    def test_missing_endpoint(self) -> None:
        self.strategy.set_settings(
            {**self.extra_settings(), f"SOCIAL_AUTH_{self.name}_OIDC_ENDPOINT": ""}
        )
        for operation, stage in (
            (self.backend.oidc_config_url, "begin"),
            (self.backend.authorization_url, "begin"),
            (self.backend.access_token_url, "token_exchange"),
            (partial(self.backend.refresh_token_url), "refresh"),
            (partial(self.backend.revoke_token_url, "token", "1234"), "disconnect"),
            (self.backend.id_token_issuer, "token_validation"),
            (self.backend.userinfo_url, "user_info"),
            (self.backend.jwks_uri, "token_validation"),
        ):
            with (
                self.subTest(operation=operation, stage=stage),
                self.assertRaises(AuthConfigurationError) as caught,
            ):
                operation()

            self.assertEqual(caught.exception.code, "missing_setting")
            self.assertEqual(caught.exception.parameter, "OIDC_ENDPOINT")
            self.assertEqual(caught.exception.stage, stage)
