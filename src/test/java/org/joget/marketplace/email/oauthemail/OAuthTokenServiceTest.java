package org.joget.marketplace.email.oauthemail;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class OAuthTokenServiceTest {
    private HttpServer server;
    private final AtomicInteger calls = new AtomicInteger();
    private final AtomicReference<String> requestBody = new AtomicReference<>();
    private final AtomicReference<String> response = new AtomicReference<>();
    private final Map<String, String> persisted = new HashMap<>();

    @Before
    public void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/token", this::handle);
        server.start();
    }

    @After
    public void stopServer() {
        server.stop(0);
    }

    @Test
    public void obtainsAndCachesClientCredentialsToken() throws Exception {
        response.set("{\"access_token\":\"access-one\",\"expires_in\":3600}");
        OAuthTokenService service = service();
        OAuthTokenService.Configuration config = config("client_credentials");

        Assert.assertEquals("access-one", service.getAccessToken(config));
        Assert.assertEquals("access-one", service.getAccessToken(config));
        Assert.assertEquals(1, calls.get());
        Assert.assertTrue(requestBody.get().contains("grant_type=client_credentials"));
        Assert.assertTrue(requestBody.get().contains("scope=mail.send+offline_access"));
        Assert.assertTrue("No plaintext token may be persisted when Joget encryption is unavailable", persisted.isEmpty());
    }

    @Test
    public void usesRefreshTokenAndPreservesItWhenProviderOmitsReplacement() throws Exception {
        response.set("{\"access_token\":\"short-lived\",\"refresh_token\":\"refresh-one\",\"expires_in\":1}");
        OAuthTokenService service = service();
        OAuthTokenService.Configuration config = config("authorization_code");
        config.authorizationCode = "one-time-code";

        Assert.assertEquals("short-lived", service.getAccessToken(config));
        response.set("{\"access_token\":\"refreshed\",\"expires_in\":3600}");
        Assert.assertEquals("refreshed", service.getAccessToken(config));
        Assert.assertEquals(2, calls.get());
        Assert.assertTrue(requestBody.get().contains("grant_type=refresh_token"));
        Assert.assertTrue(requestBody.get().contains("refresh_token=refresh-one"));
    }

    @Test
    public void exposesProviderErrorWithoutLeakingClientSecret() throws Exception {
        response.set("{\"error\":\"invalid_client\",\"error_description\":\"Client authentication failed\"}");
        try {
            service().getAccessToken(config("client_credentials"));
            Assert.fail("Expected OAuthException");
        } catch (OAuthException e) {
            Assert.assertTrue(e.getMessage().contains("Client authentication failed"));
            Assert.assertFalse(e.getMessage().contains("very-secret"));
        }
    }

    @Test
    public void requiresTenantWhenEndpointContainsPlaceholder() throws Exception {
        OAuthTokenService.Configuration config = config("client_credentials");
        config.tokenUrl = "https://login.example/{tenant}/token";
        config.tenantId = "";
        try {
            service().getAccessToken(config);
            Assert.fail("Expected OAuthException");
        } catch (OAuthException e) {
            Assert.assertEquals("OAuth Tenant ID is required", e.getMessage());
        }
    }

    private OAuthTokenService service() {
        return new OAuthTokenService(new OAuthTokenService.TokenStore() {
            @Override public String load(String key) { return persisted.get(key); }
            @Override public void save(String key, String value) { persisted.put(key, value); }
        });
    }

    private OAuthTokenService.Configuration config(String grant) {
        OAuthTokenService.Configuration config = new OAuthTokenService.Configuration();
        config.clientId = "client-id";
        config.clientSecret = "very-secret";
        config.tokenUrl = "http://127.0.0.1:" + server.getAddress().getPort() + "/token";
        config.scopes = "mail.send offline_access";
        config.grantType = grant;
        config.username = "sender@example.com";
        return config;
    }

    private void handle(HttpExchange exchange) throws IOException {
        calls.incrementAndGet();
        requestBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
        byte[] content = response.get().getBytes(StandardCharsets.UTF_8);
        int status = response.get().contains("\"error\"") ? 400 : 200;
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, content.length);
        exchange.getResponseBody().write(content);
        exchange.close();
    }
}
