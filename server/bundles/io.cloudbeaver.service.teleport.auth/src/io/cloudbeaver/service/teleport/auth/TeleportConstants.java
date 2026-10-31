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

public interface TeleportConstants {
    String AUTH_PROVIDER = "teleport";

    String DEFAULT_HEADER_NAME = "Teleport-Jwt-Assertion";
    String DEFAULT_USERNAME_CLAIM = "username";
    String DEFAULT_DISPLAY_NAME_CLAIM = "username";
    String DEFAULT_TEAMS_CLAIM = "roles";
    String FALLBACK_USERNAME_CLAIM = "sub";

    String CRED_USER = "user";
    String CRED_FULL_NAME = "fullName";
    String CRED_TEAMS = "teams";

    String TEAM_METADATA_FIELD = "teleport.role-name";

    String PARAM_JWKS_URL = "jwks-url";
    String PARAM_ISSUER = "issuer";
    String PARAM_AUDIENCE = "audience";
    String PARAM_HEADER_NAME = "header-name";
    String PARAM_USERNAME_CLAIM = "username-claim";
    String PARAM_DISPLAY_NAME_CLAIM = "display-name-claim";
    String PARAM_TEAMS_CLAIM = "teams-claim";
    String PARAM_TEAM_FILTER_PREFIX = "team-filter-prefix";
    String PARAM_TEAM_STRIP_PREFIX = "team-strip-prefix";
    String PARAM_AUTH_ROLE_CLAIM = "auth-role-claim";
    String PARAM_AUTO_USER_PROVISIONING = "auto-user-provisioning";
    String PARAM_CLOCK_SKEW_SECONDS = "clock-skew-seconds";
    String PARAM_JWKS_CACHE_TTL_SECONDS = "jwks-cache-ttl-seconds";
    String PARAM_LOGOUT_URL = "logout-url";

    int DEFAULT_CLOCK_SKEW_SECONDS = 60;
    int DEFAULT_JWKS_CACHE_TTL_SECONDS = 3600;
    int JWKS_HTTP_TIMEOUT_SECONDS = 5;
    /**
     * Shortest gap between JWKS refreshes forced by an unknown kid while the cache is still fresh.
     * Bounds how often tokens with bogus kids can make the server refetch the JWKS.
     */
    long JWKS_MIN_FORCED_REFRESH_INTERVAL_MILLIS = 30_000L;

    String ALG_RS256 = "RS256";
    String ALG_ES256 = "ES256";
}
