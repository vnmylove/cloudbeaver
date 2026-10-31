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
package io.cloudbeaver.service.auth.teleport;

import io.cloudbeaver.DBWebException;
import io.cloudbeaver.model.app.ServletAuthConfiguration;
import io.cloudbeaver.model.session.WebSession;
import io.cloudbeaver.model.session.WebSessionAuthProcessor;
import io.cloudbeaver.registry.WebAuthProviderDescriptor;
import io.cloudbeaver.registry.WebAuthProviderRegistry;
import io.cloudbeaver.server.CBApplication;
import io.cloudbeaver.service.DBWSessionHandler;
import io.cloudbeaver.utils.ServletAppUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.DBException;
import org.jkiss.dbeaver.Log;
import org.jkiss.dbeaver.model.auth.SMAuthInfo;
import org.jkiss.dbeaver.model.data.json.JSONUtils;
import org.jkiss.dbeaver.model.security.SMAuthProviderCustomConfiguration;
import org.jkiss.dbeaver.model.security.SMConstants;
import org.jkiss.dbeaver.model.security.SMController;
import org.jkiss.utils.CommonUtils;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Signs a web session in from the JWT Teleport injects when CloudBeaver is published as an application.
 * A missing or invalid token is ignored so requests that did not come through Teleport keep working.
 * Failures while creating the session are reported, because those mean the provider is misconfigured.
 */
public class TeleportSessionHandler implements DBWSessionHandler {
    private static final Log log = Log.getLog(TeleportSessionHandler.class);

    private final JwksProvider jwksProvider;

    // The handler is a singleton, so the JWKS cache is kept here and reused across session opens instead of
    // being rebuilt on every call, which would defeat the TTL cache and refetch the JWKS on each login.
    private final Object cacheLock = new Object();
    private TeleportJwksCache sharedCache;
    private String cachedJwksUrl;
    private int cachedTtlSeconds;

    public TeleportSessionHandler() {
        this(null);
    }

    /**
     * @param jwksProvider key source used instead of fetching the configured JWKS URL; tests inject a fixed key here
     */
    public TeleportSessionHandler(@Nullable JwksProvider jwksProvider) {
        this.jwksProvider = jwksProvider;
    }

    @Override
    public boolean handleSessionOpen(
        WebSession webSession,
        HttpServletRequest request,
        HttpServletResponse response
    ) throws DBException, IOException {
        if (CBApplication.getInstance().isConfigurationMode()) {
            log.warn("Teleport auth skipped: server is in configuration mode");
            return false;
        }
        ServletAuthConfiguration appConfiguration = (ServletAuthConfiguration) ServletAppUtils.getServletApplication()
            .getAppConfiguration();
        if (!appConfiguration.isAuthProviderEnabled(TeleportConstants.AUTH_PROVIDER)) {
            log.warn("Teleport auth skipped: provider is not enabled or not registered");
            return false;
        }
        authenticate(request, webSession, appConfiguration);
        return false;
    }

    private void authenticate(
        @NotNull HttpServletRequest request,
        @NotNull WebSession webSession,
        @NotNull ServletAuthConfiguration appConfiguration
    ) throws DBException {
        SMAuthProviderCustomConfiguration configuration = appConfiguration.getAuthCustomConfigurations()
            .stream()
            .filter(candidate -> TeleportConstants.AUTH_PROVIDER.equals(candidate.getProvider()))
            .filter(candidate -> !candidate.isDisabled())
            .findFirst()
            .orElse(null);
        if (configuration == null) {
            log.warn("Teleport provider is enabled but no custom configuration is set");
            return;
        }

        TeleportSettings settings;
        try {
            settings = new TeleportSettings(configuration);
        } catch (IllegalArgumentException e) {
            throw new DBWebException("Teleport configuration is incomplete", e);
        }

        String jwt = request.getHeader(settings.getHeaderName());
        if (CommonUtils.isEmpty(jwt)) {
            log.warn("Teleport auth skipped: header " + settings.getHeaderName() + " is empty");
            return;
        }

        Map<String, Object> claims;
        try {
            claims = verifier(settings).verify(jwt);
        } catch (Exception e) {
            log.warn("Teleport JWT verification failed: " + e.getMessage(), e);
            return;
        }

        String userName = JSONUtils.getString(claims, settings.getUsernameClaim());
        if (CommonUtils.isEmpty(userName)) {
            userName = JSONUtils.getString(claims, TeleportConstants.FALLBACK_USERNAME_CLAIM);
        }
        if (CommonUtils.isEmpty(userName)) {
            log.debug("Teleport JWT has no user name claim");
            return;
        }

        Map<String, Object> credentials = new HashMap<>();
        credentials.put(TeleportConstants.CRED_USER, userName);
        String displayName = JSONUtils.getString(claims, settings.getDisplayNameClaim());
        if (CommonUtils.isNotEmpty(displayName)) {
            credentials.put(TeleportConstants.CRED_FULL_NAME, displayName);
        }
        Object teams = claims.get(settings.getTeamsClaim());
        if (teams != null) {
            credentials.put(TeleportConstants.CRED_TEAMS, teams);
        }

        Map<String, Object> sessionParameters = new HashMap<>();
        String authRoleClaim = settings.getAuthRoleClaim();
        if (authRoleClaim != null) {
            String authRole = JSONUtils.getString(claims, authRoleClaim);
            if (CommonUtils.isNotEmpty(authRole)) {
                sessionParameters.put(SMConstants.SESSION_PARAM_TRUSTED_USER_ROLE, authRole);
            }
        }

        String currentSmSessionId = webSession.getUser() == null
            ? null
            : webSession.getUserContext().getSmSessionId();
        WebAuthProviderDescriptor authProvider = WebAuthProviderRegistry.getInstance()
            .getAuthProvider(TeleportConstants.AUTH_PROVIDER);
        if (authProvider == null) {
            throw new DBWebException("Auth provider " + TeleportConstants.AUTH_PROVIDER + " not found");
        }
        SMController securityController = webSession.getSecurityController();
        SMAuthInfo smAuthInfo = securityController.authenticate(
            webSession.getSessionId(),
            currentSmSessionId,
            sessionParameters,
            WebSession.CB_SESSION_TYPE,
            authProvider.getId(),
            configuration.getId(),
            credentials,
            false
        );
        new WebSessionAuthProcessor(webSession, smAuthInfo, false).authenticateSession();
    }

    @NotNull
    private TeleportJwtVerifier verifier(@NotNull TeleportSettings settings) {
        JwksProvider provider = jwksProvider != null ? jwksProvider : sharedCache(settings);
        return new TeleportJwtVerifier(provider, settings);
    }

    @NotNull
    private TeleportJwksCache sharedCache(@NotNull TeleportSettings settings) {
        synchronized (cacheLock) {
            if (sharedCache == null
                || !settings.getJwksUrl().equals(cachedJwksUrl)
                || cachedTtlSeconds != settings.getJwksCacheTtlSeconds()
            ) {
                sharedCache = new TeleportJwksCache(settings.getJwksUrl(), settings.getJwksCacheTtlSeconds());
                cachedJwksUrl = settings.getJwksUrl();
                cachedTtlSeconds = settings.getJwksCacheTtlSeconds();
            }
            return sharedCache;
        }
    }

    @Override
    public boolean handleSessionClose(WebSession webSession) throws DBException, IOException {
        return false;
    }
}
