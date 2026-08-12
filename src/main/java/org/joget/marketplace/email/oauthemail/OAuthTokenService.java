package org.joget.marketplace.email.oauthemail;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.joget.commons.util.SecurityUtil;
import org.json.JSONObject;

/** Obtains and renews OAuth tokens. Token persistence is supplied by the caller. */
public class OAuthTokenService {
    static final long EXPIRY_SKEW_SECONDS = 60;

    public interface TokenStore {
        String load(String key);
        void save(String key, String value);
    }

    public static final class Configuration {
        public String clientId;
        public String clientSecret;
        public String tenantId;
        public String tokenUrl;
        public String scopes;
        public String grantType;
        public String authorizationCode;
        public String redirectUri;
        public String refreshToken;
        public String username;

        String resolvedTokenUrl() {
            return tokenUrl == null ? "" : tokenUrl.replace("{tenant}", tenantId == null ? "" : tenantId);
        }
    }

    private final HttpClient client;
    private final TokenStore store;
    private final Map<String, JSONObject> memoryCache = new ConcurrentHashMap<>();

    public OAuthTokenService(TokenStore store) {
        this(HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).build(), store);
    }

    OAuthTokenService(HttpClient client, TokenStore store) {
        this.client = client;
        this.store = store;
    }

    public synchronized String getAccessToken(Configuration config) throws OAuthException {
        validate(config);
        String key = cacheKey(config);
        JSONObject cached = memoryCache.get(key);
        if (cached == null) cached = readCached(key);
        long now = Instant.now().getEpochSecond();
        if (cached != null && cached.optLong("expires_at", 0) > now + EXPIRY_SKEW_SECONDS
                && !cached.optString("access_token").isEmpty()) {
            return cached.getString("access_token");
        }

        String refreshToken = cached == null ? "" : cached.optString("refresh_token");
        if (refreshToken.isEmpty()) {
            refreshToken = value(config.refreshToken);
        }

        Map<String, String> parameters = new LinkedHashMap<>();
        parameters.put("client_id", value(config.clientId));
        if (!value(config.clientSecret).isEmpty()) {
            parameters.put("client_secret", config.clientSecret);
        }
        if (!value(config.scopes).isEmpty()) {
            parameters.put("scope", config.scopes.trim());
        }

        if (!refreshToken.isEmpty()) {
            parameters.put("grant_type", "refresh_token");
            parameters.put("refresh_token", refreshToken);
        } else if ("authorization_code".equals(config.grantType)) {
            if (value(config.authorizationCode).isEmpty()) {
                throw new OAuthException("OAuth authorization code is required for the initial authorization");
            }
            parameters.put("grant_type", "authorization_code");
            parameters.put("code", config.authorizationCode);
            if (!value(config.redirectUri).isEmpty()) {
                parameters.put("redirect_uri", config.redirectUri);
            }
        } else {
            parameters.put("grant_type", "client_credentials");
        }

        JSONObject token = requestToken(config.resolvedTokenUrl(), parameters);
        if (token.optString("refresh_token").isEmpty() && !refreshToken.isEmpty()) {
            token.put("refresh_token", refreshToken);
        }
        token.put("expires_at", now + Math.max(1, token.optLong("expires_in", 3600)));
        memoryCache.put(key, token);
        String encrypted = SecurityUtil.encrypt(token.toString());
        // SecurityUtil returns its input when Joget data encryption is unavailable.
        // Never persist bearer or refresh tokens in plaintext.
        if (encrypted != null && encrypted.startsWith(SecurityUtil.ENVELOPE)
                && encrypted.endsWith(SecurityUtil.ENVELOPE)) {
            store.save(key, encrypted);
        }
        return token.getString("access_token");
    }

    String cacheKey(Configuration config) throws OAuthException {
        try {
            String identity = value(config.clientId) + '|' + config.resolvedTokenUrl() + '|'
                    + value(config.username) + '|' + value(config.scopes);
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(identity.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (byte b : digest) {
                hex.append(String.format("%02x", b));
            }
            return "oauthEmailToken_" + hex;
        } catch (Exception e) {
            throw new OAuthException("Unable to create OAuth token cache key", e);
        }
    }

    private JSONObject readCached(String key) {
        try {
            String stored = store.load(key);
            return stored == null || stored.isEmpty() ? null : new JSONObject(SecurityUtil.decrypt(stored));
        } catch (Exception ignored) {
            return null;
        }
    }

    private JSONObject requestToken(String tokenUrl, Map<String, String> parameters) throws OAuthException {
        StringBuilder body = new StringBuilder();
        parameters.forEach((name, value) -> {
            if (body.length() > 0) body.append('&');
            body.append(encode(name)).append('=').append(encode(value));
        });
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(tokenUrl))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body.toString())).build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            JSONObject json = new JSONObject(response.body().isEmpty() ? "{}" : response.body());
            if (response.statusCode() < 200 || response.statusCode() >= 300 || json.optString("access_token").isEmpty()) {
                String detail = json.optString("error_description", json.optString("error", "HTTP " + response.statusCode()));
                throw new OAuthException("OAuth token request failed: " + detail);
            }
            return json;
        } catch (OAuthException e) {
            throw e;
        } catch (IllegalArgumentException e) {
            throw new OAuthException("OAuth token URL is invalid", e);
        } catch (IOException e) {
            throw new OAuthException("OAuth token endpoint could not be reached: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new OAuthException("OAuth token request was interrupted", e);
        }
    }

    private void validate(Configuration config) throws OAuthException {
        if (value(config.clientId).isEmpty()) throw new OAuthException("OAuth Client ID is required");
        if (config.resolvedTokenUrl().isEmpty()) throw new OAuthException("OAuth Token URL is required");
        if (value(config.tokenUrl).contains("{tenant}") && value(config.tenantId).isEmpty()) {
            throw new OAuthException("OAuth Tenant ID is required");
        }
        if (!"authorization_code".equals(config.grantType) && !"client_credentials".equals(config.grantType)) {
            throw new OAuthException("Unsupported OAuth grant type: " + config.grantType);
        }
    }

    private static String encode(String value) {
        return URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8);
    }

    private static String value(String value) {
        return value == null ? "" : value.trim();
    }
}
