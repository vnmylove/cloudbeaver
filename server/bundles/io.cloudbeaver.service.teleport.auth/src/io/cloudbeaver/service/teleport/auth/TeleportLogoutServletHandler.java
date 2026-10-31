/*
 * DBeaver - Universal Database Manager
 * Copyright (C) 2010-2026 DBeaver Corp and others
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.cloudbeaver.service.teleport.auth;

import io.cloudbeaver.model.app.ServletAuthConfiguration;
import io.cloudbeaver.model.session.WebSession;
import io.cloudbeaver.server.CBApplication;
import io.cloudbeaver.service.DBWServletHandler;
import io.cloudbeaver.utils.ServletAppUtils;
import jakarta.servlet.Servlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jkiss.dbeaver.DBException;
import org.jkiss.dbeaver.Log;
import org.jkiss.dbeaver.model.security.SMAuthProviderCustomConfiguration;
import org.jkiss.utils.CommonUtils;

import java.io.IOException;

/**
 * Logs the user out of CloudBeaver and bounces the browser to Teleport's own logout URL.
 *
 * <p>Why this is needed: Teleport Application Access publishes CloudBeaver behind a proxy that signs
 * every request with a JWT taken from the Teleport web session. Calling CloudBeaver's own logout only
 * clears the CB session - the very next request still carries a valid JWT, so {@link TeleportSessionHandler}
 * re-authenticates the user and it looks like logout did nothing. The real fix is to end the Teleport
 * session, which this handler does by 302ing to the configured Teleport logout URL after cleaning up
 * the CB auth state locally.</p>
 */
public class TeleportLogoutServletHandler implements DBWServletHandler {
    private static final Log log = Log.getLog(TeleportLogoutServletHandler.class);

    static final String LOGOUT_PATH = "teleport-logout";
    private static final String DEFAULT_LOGOUT_SUFFIX = "/web/logout";

    @Override
    public boolean handleRequest(Servlet servlet, HttpServletRequest request, HttpServletResponse response)
        throws DBException, IOException {
        String path = request.getRequestURI();
        if (path == null) {
            return false;
        }
        // Match both "/teleport-logout" and "<context>/teleport-logout" so this works regardless of context path.
        if (!(path.equals("/" + LOGOUT_PATH) || path.endsWith("/" + LOGOUT_PATH))) {
            return false;
        }

        try {
            WebSession webSession = CBApplication.getInstance()
                .getSessionManager()
                .getWebSession(request, response, false);
            if (webSession != null) {
                // Drop CB auth state so a stale session cannot linger past the Teleport logout.
                webSession.removeAuthInfo(TeleportConstants.AUTH_PROVIDER);
            }
        } catch (Exception e) {
            // Logging out from CB is best-effort: even if the session is gone we still want to bounce
            // the browser out of Teleport, otherwise the proxy will keep injecting a JWT.
            log.warn("Teleport logout: failed to clear web session: " + e.getMessage(), e);
        }

        String logoutUrl = resolveLogoutUrl(request);
        if (CommonUtils.isEmpty(logoutUrl)) {
            // Nothing sensible to redirect to; let the user know rather than silently going home,
            // because going home would just re-trigger the proxy JWT and re-authenticate them.
            log.warn("Teleport logout URL is not configured and could not be inferred from X-Forwarded-Host");
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Teleport logout URL not configured");
            return true;
        }

        response.setStatus(HttpServletResponse.SC_FOUND);
        response.setHeader("Cache-Control", "no-store");
        response.sendRedirect(logoutUrl);
        return true;
    }

    private String resolveLogoutUrl(HttpServletRequest request) {
        String configured = readConfiguredLogoutUrl();
        if (CommonUtils.isNotEmpty(configured)) {
            return configured;
        }
        // Fallback: derive the Teleport proxy host from X-Forwarded-Host so a missing config still gives a
        // working redirect in typical Teleport-fronted deployments.
        String forwardedHost = request.getHeader("X-Forwarded-Host");
        if (CommonUtils.isEmpty(forwardedHost)) {
            return null;
        }
        return "https://" + forwardedHost + DEFAULT_LOGOUT_SUFFIX;
    }

    private String readConfiguredLogoutUrl() {
        try {
            ServletAuthConfiguration appConfiguration = (ServletAuthConfiguration) ServletAppUtils
                .getServletApplication()
                .getAppConfiguration();
            SMAuthProviderCustomConfiguration configuration = appConfiguration.getAuthCustomConfigurations()
                .stream()
                .filter(candidate -> TeleportConstants.AUTH_PROVIDER.equals(candidate.getProvider()))
                .filter(candidate -> !candidate.isDisabled())
                .findFirst()
                .orElse(null);
            if (configuration == null) {
                return null;
            }
            return configuration.getParameter(TeleportConstants.PARAM_LOGOUT_URL);
        } catch (Exception e) {
            log.warn("Teleport logout: failed to read configuration: " + e.getMessage(), e);
            return null;
        }
    }
}
