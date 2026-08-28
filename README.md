# OAuth Email Tool for Joget DX9

A Joget Process Tool that follows the built-in Email Tool behavior while adding SMTP OAuth 2.0 (`XOAUTH2`) authentication.

To setup and configure this plugin, please see the [documentation](https://kb.joget.org/jw/web/userview/jdocs/docs/sandbox/oauth-email-tool).

## Capabilities

- OAuth authorization-code/refresh-token and client-credentials grants
- Automatic access-token acquisition and refresh before expiry
- Encrypted persistent token cache using Joget's data-encryption service
- Memory-only fallback when encryption is unavailable (tokens are never persisted as plaintext)
- Standard SMTP username/password mode for backward-compatible configurations
- To, participant recipients, CC, BCC, HTML/plain-text bodies, Joget hash variables, workflow variables, form upload attachments, filesystem/URL attachments, inline files, and send retries
- Admin-only configuration validation and OAuth token test endpoint

## OAuth configuration

Install `target/oauth-email-tool-9.0.0.jar`, select **OAuth Email Tool** in a process tool mapping, and configure the SMTP and OAuth sections.

For delegated authorization-code flows:

1. Register the redirect URI with the OAuth provider.
2. Open the configured Authorization URL externally, replacing `{tenant}` when applicable and supplying the client ID, redirect URI, response type `code`, and configured scopes.
3. Paste the returned code into **Authorization Code**, or supply an existing **Initial Refresh Token**.
4. Click **Test OAuth Token** before saving. After the first successful exchange, the refresh token is cached encrypted and renewed automatically.

For client-credentials flows, select **Client Credentials** and configure the provider-specific application permissions. SMTP providers differ in whether they permit application-only SMTP access.

Common Microsoft 365 defaults are prefilled. Google and other providers require their own authorization/token URLs and scopes.

## Build and test

```shell
mvn clean package
```

The installable bundle is generated at `target/oauth-email-tool-9.0.0.jar`.
