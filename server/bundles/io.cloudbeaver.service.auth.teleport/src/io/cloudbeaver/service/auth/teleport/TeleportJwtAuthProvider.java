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

import io.cloudbeaver.DBWUserIdentity;
import io.cloudbeaver.auth.SMAuthProviderAssigner;
import io.cloudbeaver.auth.SMAuthProviderExternal;
import io.cloudbeaver.auth.SMAutoAssign;
import io.cloudbeaver.auth.SMSignOutLinkProvider;
import io.cloudbeaver.auth.provider.local.LocalAuthSession;
import io.cloudbeaver.model.session.WebSession;
import io.cloudbeaver.model.user.WebUser;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.DBException;
import org.jkiss.dbeaver.model.DBPObject;
import org.jkiss.dbeaver.model.auth.SMSession;
import org.jkiss.dbeaver.model.data.json.JSONUtils;
import org.jkiss.dbeaver.model.runtime.DBRProgressMonitor;
import org.jkiss.dbeaver.model.security.SMAuthProviderCustomConfiguration;
import org.jkiss.dbeaver.model.security.SMController;
import org.jkiss.utils.CommonUtils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Teleport application-access provider.
 * The session handler has already verified the JWT; this class turns the verified claims into a user identity
 * and maps Teleport roles onto CloudBeaver teams through team metadata.
 */
public class TeleportJwtAuthProvider
    implements SMAuthProviderExternal<SMSession>, SMAuthProviderAssigner, SMSignOutLinkProvider {

    @NotNull
    @Override
    public Map<String, Object> authExternalUser(
        @NotNull DBRProgressMonitor monitor,
        @Nullable SMAuthProviderCustomConfiguration providerConfig,
        @NotNull Map<String, Object> authParameters
    ) throws DBException {
        // Copy rather than rebuild so claims the assigner reads (teams) survive this call.
        Map<String, Object> result = new HashMap<>(authParameters);
        if (CommonUtils.isEmpty(JSONUtils.getString(result, TeleportConstants.CRED_USER))) {
            throw new DBException("Teleport user name is empty");
        }
        return result;
    }

    @NotNull
    @Override
    public String validateLocalAuth(
        @NotNull DBRProgressMonitor monitor,
        @NotNull SMController securityController,
        @NotNull SMAuthProviderCustomConfiguration providerConfig,
        @NotNull Map<String, Object> userCredentials,
        @Nullable String activeUserId
    ) throws DBException {
        if (activeUserId != null) {
            return activeUserId;
        }
        String userName = JSONUtils.getString(userCredentials, TeleportConstants.CRED_USER);
        if (CommonUtils.isEmpty(userName)) {
            throw new DBException("Teleport user name is empty");
        }
        return userName;
    }

    @NotNull
    @Override
    public DBWUserIdentity getUserIdentity(
        @NotNull DBRProgressMonitor monitor,
        @Nullable SMAuthProviderCustomConfiguration customConfiguration,
        @NotNull Map<String, Object> authParameters
    ) throws DBException {
        String userName = JSONUtils.getString(authParameters, TeleportConstants.CRED_USER);
        if (CommonUtils.isEmpty(userName)) {
            throw new DBException("Teleport user name is empty");
        }
        String displayName = JSONUtils.getString(authParameters, TeleportConstants.CRED_FULL_NAME);
        if (CommonUtils.isEmpty(displayName)) {
            displayName = userName;
        }
        return new DBWUserIdentity(userName, displayName);
    }

    @Nullable
    @Override
    public DBPObject getUserDetails(
        @NotNull DBRProgressMonitor monitor,
        @NotNull WebSession webSession,
        @NotNull SMSession session,
        @NotNull WebUser user,
        boolean selfIdentity
    ) throws DBException {
        return null;
    }

    @Override
    public SMSession openSession(
        @NotNull DBRProgressMonitor monitor,
        @NotNull SMSession mainSession,
        @Nullable SMAuthProviderCustomConfiguration customConfiguration,
        @NotNull Map<String, Object> userCredentials
    ) throws DBException {
        return new LocalAuthSession(mainSession, JSONUtils.getString(userCredentials, TeleportConstants.CRED_USER));
    }

    @Override
    public void closeSession(@NotNull SMSession mainSession, SMSession session) throws DBException {
        // Nothing to do here. Proper sign-out ends the Teleport session via the logout URL,
        // which stops the proxy from sending a JWT for the next request.
    }

    @Override
    public void refreshSession(
        @NotNull DBRProgressMonitor monitor,
        @NotNull SMSession mainSession,
        SMSession session
    ) throws DBException {
    }

    @NotNull
    @Override
    public SMAutoAssign detectAutoAssignments(
        @NotNull DBRProgressMonitor monitor,
        @Nullable SMAuthProviderCustomConfiguration providerConfig,
        @NotNull Map<String, Object> authParameters
    ) throws DBException {
        SMAutoAssign autoAssign = new SMAutoAssign();
        if (providerConfig == null) {
            return autoAssign;
        }
        TeleportSettings settings = new TeleportSettings(providerConfig);
        for (String teamId : resolveTeamIds(authParameters.get(TeleportConstants.CRED_TEAMS), settings)) {
            autoAssign.addExternalTeamId(teamId);
        }
        String authRoleClaim = settings.getAuthRoleClaim();
        if (authRoleClaim != null) {
            String authRole = JSONUtils.getString(authParameters, authRoleClaim);
            if (CommonUtils.isNotEmpty(authRole)) {
                autoAssign.setAuthRole(authRole);
            }
        }
        return autoAssign;
    }

    @Nullable
    @Override
    public String getExternalTeamIdMetadataFieldName() {
        return TeleportConstants.TEAM_METADATA_FIELD;
    }

    @NotNull
    @Override
    public String getCommonSignOutLink(
        @NotNull String providerId,
        @NotNull Map<String, Object> providerConfig,
        @NotNull String origin
    ) throws DBException {
        Object logoutUrl = providerConfig.get(TeleportConstants.PARAM_LOGOUT_URL);
        return logoutUrl == null ? "" : logoutUrl.toString();
    }

    @Override
    public String getUserSignOutLink(
        @NotNull SMAuthProviderCustomConfiguration providerConfig,
        @NotNull Map<String, Object> userCredentials,
        @NotNull String origin
    ) throws DBException {
        return providerConfig.getParameter(TeleportConstants.PARAM_LOGOUT_URL);
    }

    @NotNull
    static List<String> resolveTeamIds(@Nullable Object rawTeams, @NotNull TeleportSettings settings) {
        List<String> values = new ArrayList<>();
        if (rawTeams instanceof Collection<?> collection) {
            for (Object value : collection) {
                if (value != null) {
                    values.add(String.valueOf(value));
                }
            }
        } else if (rawTeams instanceof String text && CommonUtils.isNotEmpty(text)) {
            for (String value : text.split(",")) {
                values.add(value.trim());
            }
        }
        List<String> resolved = new ArrayList<>();
        String filterPrefix = settings.getTeamFilterPrefix();
        String stripPrefix = settings.getTeamStripPrefix();
        for (String value : values) {
            if (CommonUtils.isEmpty(value)) {
                continue;
            }
            if (filterPrefix != null && !value.startsWith(filterPrefix)) {
                continue;
            }
            if (stripPrefix != null && value.startsWith(stripPrefix)) {
                value = value.substring(stripPrefix.length());
            }
            if (CommonUtils.isNotEmpty(value)) {
                resolved.add(value);
            }
        }
        return resolved;
    }
}
