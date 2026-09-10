package org.joget.marketplace.email.oauthemail;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import javax.mail.Authenticator;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import org.apache.commons.mail.EmailException;
import org.apache.commons.mail.HtmlEmail;
import org.joget.apps.app.model.AppDefinition;
import org.joget.apps.app.service.AppUtil;
import org.joget.commons.util.DynamicDataSourceManager;
import org.joget.commons.util.LogUtil;
import org.joget.commons.util.PluginThread;
import org.joget.commons.util.SecurityUtil;
import org.joget.commons.util.SetupManager;
import org.joget.commons.util.StringUtil;
import org.joget.plugin.base.DefaultApplicationPlugin;
import org.joget.plugin.base.PluginException;
import org.joget.plugin.base.PluginWebSupport;
import org.joget.workflow.model.WorkflowAssignment;
import org.joget.workflow.model.service.WorkflowUserManager;
import org.joget.workflow.util.WorkflowUtil;
import org.json.JSONArray;
import org.json.JSONObject;

public class OAuthEmailTool extends DefaultApplicationPlugin implements PluginWebSupport {
    private static final String CLASS_NAME = OAuthEmailTool.class.getName();
    private static final HttpClient GRAPH_HTTP_CLIENT = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NORMAL).build();

    @Override public String getName() { return "OAuth Email Tool"; }
    @Override public String getLabel() { return "OAuth Email Tool"; }
    @Override public String getDescription() { return "Sends email using SMTP (OAuth 2.0 or password) or the Microsoft Graph API"; }
    @Override public String getVersion() { return "9.0.1"; }
    @Override public String getClassName() { return getClass().getName(); }
    @Override public String getPluginIcon() { return "<i class=\"las la-envelope-open-text\"></i>"; }

    @Override
    public String getPropertyOptions() {
        return AppUtil.readPluginResource(getClassName(), "/properties/oauthEmailTool.json", null, true,
                "messages/OAuthEmailTool");
    }

    @Override
    public Object execute(Map properties) {
        WorkflowAssignment assignment = (WorkflowAssignment) properties.get("workflowAssignment");
        AppDefinition appDef = (AppDefinition) properties.get("appDef");
        try {
            String authMode = string(properties.get("authMode"));
            BuiltEmail built = buildEmail(properties, assignment, appDef);
            String recipients = addRecipients(built.email, properties, assignment, appDef);
            AppUtil.emailAttachment(properties, assignment, appDef, built.email);

            final String profile = DynamicDataSourceManager.getCurrentProfile();
            int retryCount = AppUtil.getEmailRetryCount((String) properties.get("retryCount"));
            long retryInterval = AppUtil.getEmailRetryInterval((String) properties.get("retryInterval"));
            Thread thread;
            if ("graph".equals(authMode)) {
                built.email.buildMimeMessage();
                thread = new PluginThread(() -> sendViaGraphWithRetry(built.email, recipients, built.graphAccessToken,
                        built.graphSendMailUrl, retryCount, retryInterval));
            } else {
                thread = new PluginThread(() -> sendWithRetry(built.email, recipients, retryCount, retryInterval));
            }
            thread.setName("OAuthEmailTool-" + (profile == null ? "default" : profile));
            thread.setDaemon(true);
            thread.start();
        } catch (Exception e) {
            LogUtil.error(CLASS_NAME, e, "OAuth Email Tool failed: " + safeMessage(e));
        }
        return null;
    }

    private static final class BuiltEmail {
        final HtmlEmail email;
        final String graphAccessToken;
        final String graphSendMailUrl;
        BuiltEmail(HtmlEmail email, String graphAccessToken, String graphSendMailUrl) {
            this.email = email;
            this.graphAccessToken = graphAccessToken;
            this.graphSendMailUrl = graphSendMailUrl;
        }
    }

    private BuiltEmail buildEmail(Map properties, WorkflowAssignment assignment, AppDefinition appDef) throws Exception {
        String from = WorkflowUtil.processVariable((String) properties.get("from"), (String) properties.get("formDataTable"), assignment);
        String authMode = string(properties.get("authMode"));
        if (from == null || from.isEmpty()) throw new PluginException("From email address is required");

        HtmlEmail email;
        String graphAccessToken = null;
        String graphSendMailUrl = null;
        if ("graph".equals(authMode)) {
            OAuthTokenService.Configuration config = oauthConfiguration(properties, assignment, appDef, from);
            graphAccessToken = tokenService().getAccessToken(config);
            String template = hash(properties, "sendMailUrl", assignment, appDef);
            if (template.isEmpty()) throw new PluginException("Microsoft Graph Send Mail Endpoint is required");
            graphSendMailUrl = resolveGraphUrl(template, from);
            email = createGraphEmail(from);
        } else {
            String host = hash(properties, "host", assignment, appDef);
            String port = hash(properties, "port", assignment, appDef);
            String security = hash(properties, "security", assignment, appDef);
            String username = hash(properties, "username", assignment, appDef);
            String password = decryptHash(properties, "password", assignment, appDef);
            if (host.isEmpty()) throw new PluginException("SMTP host is required");
            if (username.isEmpty()) throw new PluginException("SMTP username is required");

            if ("password".equals(authMode)) {
                email = AppUtil.createEmail(host, port, security, username, password, from);
            } else {
                OAuthTokenService.Configuration config = oauthConfiguration(properties, assignment, appDef, username);
                String accessToken = tokenService().getAccessToken(config);
                email = createOAuthEmail(host, port, security, username, accessToken, from);
            }
        }
        if (email == null) throw new PluginException("Unable to create email session");

        String subject = WorkflowUtil.processVariable((String) properties.get("subject"), (String) properties.get("formDataTable"), assignment);
        boolean html = "true".equalsIgnoreCase(string(properties.get("isHtml")));
        Map<String, String> replacements = null;
        if (html) {
            replacements = new HashMap<>();
            replacements.put("\\n", "<br/>");
        }
        String message = AppUtil.processHashVariable((String) properties.get("message"), assignment, null, replacements);
        email.setSubject(subject);
        email.setCharset("UTF-8");
        if (html) email.setHtmlMsg(message); else email.setMsg(message);
        return new BuiltEmail(email, graphAccessToken, graphSendMailUrl);
    }

    private HtmlEmail createGraphEmail(String from) throws EmailException {
        HtmlEmail email = new HtmlEmail();
        email.setMailSession(Session.getInstance(new Properties()));
        email.setFrom(StringUtil.encodeEmail(from));
        return email;
    }

    private static String resolveGraphUrl(String template, String from) {
        return template.replace("{SENDER_EMAIL}", from).replace("{from}", from);
    }

    private HtmlEmail createOAuthEmail(String host, String port, String security, String username,
            String accessToken, String from) throws EmailException {
        Properties mail = new Properties();
        mail.put("mail.smtp.host", host);
        if (!port.isEmpty()) mail.put("mail.smtp.port", port);
        mail.put("mail.smtp.auth", "true");
        mail.put("mail.smtp.auth.mechanisms", "XOAUTH2");
        mail.put("mail.smtp.auth.login.disable", "true");
        mail.put("mail.smtp.auth.plain.disable", "true");
        mail.put("mail.smtp.ssl.checkserveridentity", "true");
        if ("SSL".equalsIgnoreCase(security)) {
            mail.put("mail.smtp.ssl.enable", "true");
        } else if ("TLS".equalsIgnoreCase(security)) {
            mail.put("mail.smtp.starttls.enable", "true");
            mail.put("mail.smtp.starttls.required", "true");
        }
        Session session = Session.getInstance(mail, new Authenticator() {
            @Override protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(username, accessToken);
            }
        });
        HtmlEmail email = new HtmlEmail();
        email.setMailSession(session);
        email.setAuthentication(username, accessToken);
        email.setFrom(StringUtil.encodeEmail(from));
        return email;
    }

    private String addRecipients(HtmlEmail email, Map properties, WorkflowAssignment assignment,
            AppDefinition appDef) throws Exception {
        addAddresses(email, "cc", properties, assignment, appDef);
        addAddresses(email, "bcc", properties, assignment, appDef);
        String participant = string(properties.get("toParticipantId"));
        String specific = string(properties.get("toSpecific"));
        if (participant.trim().isEmpty() && specific.trim().isEmpty()) throw new PluginException("No email recipient specified");
        Collection<String> addresses = AppUtil.getEmailList(participant, specific, assignment, appDef);
        StringBuilder output = new StringBuilder();
        for (String address : addresses) {
            email.addTo(StringUtil.encodeEmail(address));
            if (output.length() > 0) output.append(", ");
            output.append(address);
        }
        if (output.length() == 0) throw new PluginException("No valid email recipient resolved");
        return output.toString();
    }

    private void addAddresses(HtmlEmail email, String type, Map properties, WorkflowAssignment assignment,
            AppDefinition appDef) throws Exception {
        String value = string(properties.get(type));
        if (value.isEmpty()) return;
        for (String address : AppUtil.getEmailList(null, value, assignment, appDef)) {
            if ("cc".equals(type)) email.addCc(StringUtil.encodeEmail(address));
            else email.addBcc(StringUtil.encodeEmail(address));
        }
    }

    private void sendWithRetry(HtmlEmail email, String recipients, int retryCount, long retryInterval) {
        for (int attempt = 0; attempt <= retryCount; attempt++) {
            try {
                if (attempt > 0) Thread.sleep(retryInterval);
                LogUtil.info(CLASS_NAME, "Sending email from=" + email.getFromAddress() + ", to=" + recipients
                        + ", subject=" + email.getSubject() + (attempt == 0 ? "" : ", attempt=" + attempt));
                if (attempt == 0) email.send(); else email.sendMimeMessage();
                LogUtil.info(CLASS_NAME, "Email sent successfully, subject=" + email.getSubject());
                return;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                LogUtil.error(CLASS_NAME, e, "Email retry interrupted");
                return;
            } catch (EmailException e) {
                LogUtil.error(CLASS_NAME, e, "SMTP send failed" + (attempt < retryCount ? "; retrying" : "; retries exhausted"));
            }
        }
    }

    private void sendViaGraphWithRetry(HtmlEmail email, String recipients, String accessToken, String sendMailUrl,
            int retryCount, long retryInterval) {
        String payload;
        try {
            ByteArrayOutputStream raw = new ByteArrayOutputStream();
            email.getMimeMessage().writeTo(raw);
            payload = Base64.getEncoder().encodeToString(raw.toByteArray());
        } catch (Exception e) {
            LogUtil.error(CLASS_NAME, e, "Unable to serialize MIME message for Microsoft Graph send");
            return;
        }
        for (int attempt = 0; attempt <= retryCount; attempt++) {
            try {
                if (attempt > 0) Thread.sleep(retryInterval);
                LogUtil.info(CLASS_NAME, "Sending email via Microsoft Graph from=" + email.getFromAddress()
                        + ", to=" + recipients + ", subject=" + email.getSubject()
                        + (attempt == 0 ? "" : ", attempt=" + attempt));
                HttpRequest request = HttpRequest.newBuilder(URI.create(sendMailUrl))
                        .header("Authorization", "Bearer " + accessToken)
                        .header("Content-Type", "text/plain")
                        .POST(HttpRequest.BodyPublishers.ofString(payload))
                        .build();
                HttpResponse<String> response = GRAPH_HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() >= 200 && response.statusCode() < 300) {
                    LogUtil.info(CLASS_NAME, "Email sent successfully via Microsoft Graph, subject=" + email.getSubject());
                    return;
                }
                LogUtil.error(CLASS_NAME, null, "Microsoft Graph send failed, status=" + response.statusCode()
                        + ", body=" + response.body() + (attempt < retryCount ? "; retrying" : "; retries exhausted"));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                LogUtil.error(CLASS_NAME, e, "Email retry interrupted");
                return;
            } catch (IOException e) {
                LogUtil.error(CLASS_NAME, e, "Microsoft Graph send failed"
                        + (attempt < retryCount ? "; retrying" : "; retries exhausted"));
            }
        }
    }

    private OAuthTokenService.Configuration oauthConfiguration(Map properties, WorkflowAssignment assignment,
            AppDefinition appDef, String username) {
        OAuthTokenService.Configuration config = new OAuthTokenService.Configuration();
        config.clientId = hash(properties, "clientId", assignment, appDef);
        config.clientSecret = decryptHash(properties, "clientSecret", assignment, appDef);
        config.tenantId = hash(properties, "tenantId", assignment, appDef);
        config.tokenUrl = hash(properties, "tokenUrl", assignment, appDef);
        config.scopes = hash(properties, "scopes", assignment, appDef);
        config.grantType = string(properties.get("grantType"));
        config.authorizationCode = decryptHash(properties, "authorizationCode", assignment, appDef);
        config.redirectUri = hash(properties, "redirectUri", assignment, appDef);
        config.refreshToken = decryptHash(properties, "refreshToken", assignment, appDef);
        config.username = username;
        return config;
    }

    private OAuthTokenService tokenService() {
        SetupManager manager = (SetupManager) AppUtil.getApplicationContext().getBean("setupManager");
        return new OAuthTokenService(new OAuthTokenService.TokenStore() {
            @Override public String load(String key) { return manager.getSettingValue(key); }
            @Override public void save(String key, String value) { manager.updateSetting(key, value); }
        });
    }

    private String hash(Map properties, String key, WorkflowAssignment assignment, AppDefinition appDef) {
        return string(AppUtil.processHashVariable(string(properties.get(key)), assignment, null, null, appDef));
    }

    private String decryptHash(Map properties, String key, WorkflowAssignment assignment, AppDefinition appDef) {
        return string(AppUtil.processHashVariable(SecurityUtil.decrypt(string(properties.get(key))), assignment, null, null, appDef));
    }

    @Override
    public void webService(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.setContentType("application/json;charset=UTF-8");
        if (!WorkflowUtil.isCurrentUserInRole(WorkflowUserManager.ROLE_ADMIN)) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }
        JSONObject result = new JSONObject();
        String action = request.getParameter("action");
        try {
            if ("validate".equals(action)) {
                require(request, "from", "From address");
                if (!"graph".equals(string(request.getParameter("authMode")))) {
                    require(request, "host", "SMTP host");
                    require(request, "port", "SMTP port");
                    require(request, "username", "SMTP username");
                }
                result.put("status", "success");
            } else if ("testtoken".equals(action)) {
                AppDefinition appDef = AppUtil.getCurrentAppDefinition();
                Map<String, String> values = requestParameters(request);
                // Must match buildEmail()'s identity or this test's cached token won't be reused by the real send.
                String identity = "graph".equals(string(request.getParameter("authMode")))
                        ? hash(values, "from", null, appDef)
                        : hash(values, "username", null, appDef);
                OAuthTokenService.Configuration config = oauthConfiguration(values, null, appDef, identity);
                tokenService().getAccessToken(config);
                result.put("message", "OAuth access token obtained successfully.");
            } else {
                response.setStatus(HttpServletResponse.SC_NO_CONTENT);
                return;
            }
        } catch (Exception e) {
            LogUtil.error(CLASS_NAME, e, "OAuth Email Tool configuration test failed");
            result.put("status", "fail");
            if ("validate".equals(action)) {                
                result.put("message", new JSONArray());
            } else {
                result.put("message", safeMessage(e));
            }
        }
        result.write(response.getWriter());
    }

    private Map<String, String> requestParameters(HttpServletRequest request) {
        Map<String, String> values = new HashMap<>();
        for (String name : new String[]{"username", "from", "clientId", "clientSecret", "tenantId", "tokenUrl",
                "scopes", "grantType", "authorizationCode", "redirectUri", "refreshToken"}) {
            values.put(name, request.getParameter(name));
        }
        return values;
    }

    private void require(HttpServletRequest request, String name, String label) throws PluginException {
        if (string(request.getParameter(name)).isEmpty()) throw new PluginException(label + " is required");
    }

    private static String safeMessage(Throwable e) {
        String message = e.getMessage();
        return message == null || message.isBlank() ? e.getClass().getSimpleName() : message;
    }

    private static String string(Object value) { return value == null ? "" : value.toString(); }
}
