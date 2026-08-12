package org.joget.marketplace.email.oauthemail;

import java.io.IOException;
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

    @Override public String getName() { return "OAuth Email Tool"; }
    @Override public String getLabel() { return "OAuth Email Tool"; }
    @Override public String getDescription() { return "Sends email using OAuth 2.0 or standard SMTP authentication"; }
    @Override public String getVersion() { return "1.0.0"; }
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
            HtmlEmail email = buildEmail(properties, assignment, appDef);
            String recipients = addRecipients(email, properties, assignment, appDef);
            AppUtil.emailAttachment(properties, assignment, appDef, email);

            final String profile = DynamicDataSourceManager.getCurrentProfile();
            int retryCount = AppUtil.getEmailRetryCount((String) properties.get("retryCount"));
            long retryInterval = AppUtil.getEmailRetryInterval((String) properties.get("retryInterval"));
            Thread thread = new PluginThread(() -> sendWithRetry(email, recipients, retryCount, retryInterval));
            thread.setName("OAuthEmailTool-" + (profile == null ? "default" : profile));
            thread.setDaemon(true);
            thread.start();
        } catch (Exception e) {
            LogUtil.error(CLASS_NAME, e, "OAuth Email Tool failed: " + safeMessage(e));
        }
        return null;
    }

    private HtmlEmail buildEmail(Map properties, WorkflowAssignment assignment, AppDefinition appDef) throws Exception {
        String host = hash(properties, "host", assignment, appDef);
        String port = hash(properties, "port", assignment, appDef);
        String security = hash(properties, "security", assignment, appDef);
        String username = hash(properties, "username", assignment, appDef);
        String password = decryptHash(properties, "password", assignment, appDef);
        String from = WorkflowUtil.processVariable((String) properties.get("from"), (String) properties.get("formDataTable"), assignment);
        String authMode = string(properties.get("authMode"));

        if (host.isEmpty()) throw new PluginException("SMTP host is required");
        if (from == null || from.isEmpty()) throw new PluginException("From email address is required");
        if (username.isEmpty()) throw new PluginException("SMTP username is required");

        HtmlEmail email;
        if ("password".equals(authMode)) {
            email = AppUtil.createEmail(host, port, security, username, password, from);
        } else {
            OAuthTokenService.Configuration config = oauthConfiguration(properties, assignment, appDef, username);
            String accessToken = tokenService().getAccessToken(config);
            email = createOAuthEmail(host, port, security, username, accessToken, from);
        }
        if (email == null) throw new PluginException("Unable to create SMTP email session");

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
        return email;
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
                require(request, "host", "SMTP host");
                require(request, "port", "SMTP port");
                require(request, "from", "From address");
                require(request, "username", "SMTP username");
                result.put("status", "success");
            } else if ("testtoken".equals(action)) {
                AppDefinition appDef = AppUtil.getCurrentAppDefinition();
                Map<String, String> values = requestParameters(request);
                OAuthTokenService.Configuration config = oauthConfiguration(values, null, appDef,
                        hash(values, "username", null, appDef));
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
                // Joget's AJAX property validator expects an array. An empty array
                // makes it display default_error_message from the property JSON.
                result.put("message", new JSONArray());
            } else {
                result.put("message", safeMessage(e));
            }
        }
        result.write(response.getWriter());
    }

    private Map<String, String> requestParameters(HttpServletRequest request) {
        Map<String, String> values = new HashMap<>();
        for (String name : new String[]{"username", "clientId", "clientSecret", "tenantId", "tokenUrl",
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
