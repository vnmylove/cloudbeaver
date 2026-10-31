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

import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.model.security.SMAuthProviderCustomConfiguration;
import org.jkiss.utils.CommonUtils;

/**
 * Reads and validates a Teleport auth provider configuration.
 * Required values fail fast so a misconfigured provider is visible instead of failing later with a null pointer.
 */
public class TeleportSettings {
    @NotNull
    private final String jwksUrl;
    @NotNull
    private final String issuer;
    @NotNull
    private final String audience;
    @NotNull
    private final String headerName;
    @NotNull
    private final String usernameClaim;
    @NotNull
    private final String displayNameClaim;
    @NotNull
    private final String teamsClaim;
    @Nullable
    private final String teamFilterPrefix;
    @Nullable
    private final String teamStripPrefix;
    @Nullable
    private final String authRoleClaim;
    private final boolean autoUserProvisioning;
    private final int clockSkewSeconds;
    private final int jwksCacheTtlSeconds;
    @Nullable
    private final String logoutUrl;

    public TeleportSettings(@Nullable SMAuthProviderCustomConfiguration providerConfiguration) {
        if (providerConfiguration == null) {
            throw new IllegalArgumentException("Teleport provider configuration is null");
        }
        this.jwksUrl = required(providerConfiguration, TeleportConstants.PARAM_JWKS_URL);
        this.issuer = required(providerConfiguration, TeleportConstants.PARAM_ISSUER);
        this.audience = required(providerConfiguration, TeleportConstants.PARAM_AUDIENCE);
        this.headerName = providerConfiguration.getParameterOrDefault(
            TeleportConstants.PARAM_HEADER_NAME, TeleportConstants.DEFAULT_HEADER_NAME);
        this.usernameClaim = providerConfiguration.getParameterOrDefault(
            TeleportConstants.PARAM_USERNAME_CLAIM, TeleportConstants.DEFAULT_USERNAME_CLAIM);
        this.displayNameClaim = providerConfiguration.getParameterOrDefault(
            TeleportConstants.PARAM_DISPLAY_NAME_CLAIM, TeleportConstants.DEFAULT_DISPLAY_NAME_CLAIM);
        this.teamsClaim = providerConfiguration.getParameterOrDefault(
            TeleportConstants.PARAM_TEAMS_CLAIM, TeleportConstants.DEFAULT_TEAMS_CLAIM);
        this.teamFilterPrefix = emptyToNull(providerConfiguration.getParameter(TeleportConstants.PARAM_TEAM_FILTER_PREFIX));
        this.teamStripPrefix = emptyToNull(providerConfiguration.getParameter(TeleportConstants.PARAM_TEAM_STRIP_PREFIX));
        this.authRoleClaim = emptyToNull(providerConfiguration.getParameter(TeleportConstants.PARAM_AUTH_ROLE_CLAIM));
        this.autoUserProvisioning = CommonUtils.toBoolean(
            providerConfiguration.getParameter(TeleportConstants.PARAM_AUTO_USER_PROVISIONING), true);
        // A negative skew would narrow the exp/nbf window and reject otherwise valid tokens, so floor it at zero.
        this.clockSkewSeconds = Math.max(0, parseInt(
            providerConfiguration.getParameter(TeleportConstants.PARAM_CLOCK_SKEW_SECONDS),
            TeleportConstants.DEFAULT_CLOCK_SKEW_SECONDS));
        this.jwksCacheTtlSeconds = parseInt(
            providerConfiguration.getParameter(TeleportConstants.PARAM_JWKS_CACHE_TTL_SECONDS),
            TeleportConstants.DEFAULT_JWKS_CACHE_TTL_SECONDS);
        this.logoutUrl = emptyToNull(providerConfiguration.getParameter(TeleportConstants.PARAM_LOGOUT_URL));
    }

    @NotNull
    private static String required(
        @NotNull SMAuthProviderCustomConfiguration configuration,
        @NotNull String name
    ) {
        String value = configuration.getParameter(name);
        if (CommonUtils.isEmpty(value)) {
            throw new IllegalArgumentException("Teleport configuration is missing required property '" + name + "'");
        }
        return value;
    }

    @Nullable
    private static String emptyToNull(@Nullable String value) {
        return CommonUtils.isEmpty(value) ? null : value;
    }

    private static int parseInt(@Nullable String value, int defaultValue) {
        if (CommonUtils.isEmpty(value)) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    @NotNull
    public String getJwksUrl() {
        return jwksUrl;
    }

    @NotNull
    public String getIssuer() {
        return issuer;
    }

    @NotNull
    public String getAudience() {
        return audience;
    }

    @NotNull
    public String getHeaderName() {
        return headerName;
    }

    @NotNull
    public String getUsernameClaim() {
        return usernameClaim;
    }

    @NotNull
    public String getDisplayNameClaim() {
        return displayNameClaim;
    }

    @NotNull
    public String getTeamsClaim() {
        return teamsClaim;
    }

    @Nullable
    public String getTeamFilterPrefix() {
        return teamFilterPrefix;
    }

    @Nullable
    public String getTeamStripPrefix() {
        return teamStripPrefix;
    }

    @Nullable
    public String getAuthRoleClaim() {
        return authRoleClaim;
    }

    public boolean isAutoUserProvisioning() {
        return autoUserProvisioning;
    }

    public int getClockSkewSeconds() {
        return clockSkewSeconds;
    }

    public int getJwksCacheTtlSeconds() {
        return jwksCacheTtlSeconds;
    }

    @Nullable
    public String getLogoutUrl() {
        return logoutUrl;
    }
}
