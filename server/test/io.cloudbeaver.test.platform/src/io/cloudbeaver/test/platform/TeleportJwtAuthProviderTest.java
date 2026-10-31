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
package io.cloudbeaver.test.platform;

import io.cloudbeaver.service.teleport.auth.TeleportConstants;
import io.cloudbeaver.service.teleport.auth.TeleportJwtAuthProvider;
import io.cloudbeaver.service.teleport.auth.TeleportSettings;

import io.cloudbeaver.auth.SMAutoAssign;
import org.jkiss.dbeaver.model.security.SMAuthProviderCustomConfiguration;
import org.junit.Assert;
import org.junit.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class TeleportJwtAuthProviderTest {
    private final TeleportJwtAuthProvider provider = new TeleportJwtAuthProvider();

    @Test
    public void authExternalUserIsIdempotentAndKeepsTeams() throws Exception {
        Map<String, Object> credentials = new LinkedHashMap<>();
        credentials.put(TeleportConstants.CRED_USER, "alice");
        credentials.put(TeleportConstants.CRED_FULL_NAME, "Alice");
        credentials.put(TeleportConstants.CRED_TEAMS, List.of("editor", "admin"));

        Map<String, Object> first = provider.authExternalUser(null, configuration(), credentials);
        Map<String, Object> second = provider.authExternalUser(null, configuration(), first);

        Assert.assertEquals(first, second);
        Assert.assertEquals(List.of("editor", "admin"), second.get(TeleportConstants.CRED_TEAMS));
        Assert.assertEquals("alice", credentials.get(TeleportConstants.CRED_USER));
    }

    @Test
    public void rejectsMissingUserName() {
        Assert.assertThrows(
            Exception.class,
            () -> provider.authExternalUser(null, configuration(), Map.of()));
    }

    @Test
    public void returnsNoAssignmentsWhenConfigurationIsMissing() throws Exception {
        SMAutoAssign assignments = provider.detectAutoAssignments(null, null, Map.of());
        Assert.assertTrue(assignments.getExternalTeamIds().isEmpty());
        Assert.assertNull(assignments.getAuthRole());
    }

    @Test
    public void filtersAndStripsTeamIds() throws Exception {
        SMAuthProviderCustomConfiguration configuration = configuration();
        configuration.setParameters(Map.of(
            TeleportConstants.PARAM_JWKS_URL, "https://teleport.example/.well-known/jwks.json",
            TeleportConstants.PARAM_ISSUER, "localhost.local",
            TeleportConstants.PARAM_AUDIENCE, "cloudbeaver",
            TeleportConstants.PARAM_TEAM_FILTER_PREFIX, "prefix-",
            TeleportConstants.PARAM_TEAM_STRIP_PREFIX, "prefix-"
        ));
        Map<String, Object> credentials = Map.of(
            TeleportConstants.CRED_TEAMS, List.of("prefix-editor", "prefix-admin", "other"));

        SMAutoAssign assignments = provider.detectAutoAssignments(null, configuration, credentials);
        Assert.assertEquals(List.of("editor", "admin"), assignments.getExternalTeamIds());
    }

    @Test
    public void splitsTeamIdsProvidedAsText() throws Exception {
        Map<String, Object> credentials = Map.of(TeleportConstants.CRED_TEAMS, "editor, admin,");
        SMAutoAssign assignments = provider.detectAutoAssignments(null, configuration(), credentials);
        Assert.assertEquals(List.of("editor", "admin"), assignments.getExternalTeamIds());
    }

    @Test
    public void readsAuthRoleFromConfiguredClaim() throws Exception {
        SMAuthProviderCustomConfiguration configuration = configuration();
        Map<String, Object> parameters = new LinkedHashMap<>(configuration.getParameters());
        parameters.put(TeleportConstants.PARAM_AUTH_ROLE_CLAIM, "cbRole");
        configuration.setParameters(parameters);

        SMAutoAssign assignments = provider.detectAutoAssignments(
            null, configuration, Map.of("cbRole", "admin"));
        Assert.assertEquals("admin", assignments.getAuthRole());
    }

    @Test
    public void reportsTeamMetadataField() {
        Assert.assertEquals(TeleportConstants.TEAM_METADATA_FIELD, provider.getExternalTeamIdMetadataFieldName());
    }

    @Test
    public void rejectsConfigurationWithoutRequiredValues() {
        Assert.assertThrows(IllegalArgumentException.class, () -> new TeleportSettings(null));
        SMAuthProviderCustomConfiguration configuration = new SMAuthProviderCustomConfiguration("teleport");
        configuration.setParameters(Map.of(TeleportConstants.PARAM_JWKS_URL, "https://teleport.example/jwks"));
        Assert.assertThrows(IllegalArgumentException.class, () -> new TeleportSettings(configuration));
    }

    private static SMAuthProviderCustomConfiguration configuration() {
        SMAuthProviderCustomConfiguration configuration = new SMAuthProviderCustomConfiguration("teleport");
        configuration.setProvider(TeleportConstants.AUTH_PROVIDER);
        configuration.setParameters(Map.of(
            TeleportConstants.PARAM_JWKS_URL, "https://teleport.example/.well-known/jwks.json",
            TeleportConstants.PARAM_ISSUER, "localhost.local",
            TeleportConstants.PARAM_AUDIENCE, "cloudbeaver"
        ));
        return configuration;
    }
}
