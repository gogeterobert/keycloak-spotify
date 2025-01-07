/*
 * Copyright 2018 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.social.spotify;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.ErrorPageException;
import org.keycloak.services.messages.Messages;
import org.keycloak.models.*;

import java.util.Set;
import java.io.IOException;

/**
 * @author <a href="">Robert Gogete</a>
 */
public class SpotifyIdentityProvider extends AbstractOAuth2IdentityProvider
        implements SocialIdentityProvider {

    private static final Logger log = Logger.getLogger(SpotifyIdentityProvider.class);

    public static final String AUTH_URL = "https://accounts.spotify.com/authorize";
    public static final String TOKEN_URL = "https://accounts.spotify.com/api/token";
    public static final String PROFILE_URL = "https://api.spotify.com/v1/me";
    public static final String DEFAULT_SCOPE = "user-read-email";

    public SpotifyIdentityProvider(KeycloakSession session, OAuth2IdentityProviderConfig config) {
        super(session, config);
        log.debugf("Creating Spotify Identity Provider with config: %s", config);
        config.setAuthorizationUrl(AUTH_URL);
        config.setTokenUrl(TOKEN_URL);
        config.setUserInfoUrl(PROFILE_URL);
    }

    @Override
    protected boolean supportsExternalExchange() {
        return true;
    }

    @Override
    protected String getProfileEndpointForValidation(EventBuilder event) {
        return PROFILE_URL;
    }

        @Override
    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
        BrokeredIdentityContext user = new BrokeredIdentityContext(getJsonProperty(profile, "id"), getConfig());

        // profile only contains email property if user-read-email scope is used
        String email = getJsonProperty(profile, "email");
        if (email != null) {
            user.setEmail(email);
        }

        user.setIdp(this);

        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());

        return user;
    }

    @Override
    protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
        try {
            BrokeredIdentityContext identity = extractIdentityFromProfile(null, doHttpGet(PROFILE_URL, accessToken));

            if (identity.getUsername() == null) {
                // if user-read-email scope has been requested, then use email as the username
                // otherwise use Spotify id
                String email = identity.getEmail();
                if (email != null) {
                    identity.setUsername(email);
                }
                else {
                    identity.setUsername(identity.getId());
                }
            }

            return identity;
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not obtain user profile from spotify.", e);
        }
    }

    private JsonNode doHttpGet(String url, String bearerToken) throws IOException {
        JsonNode response = SimpleHttp.doGet(url, session).header("Authorization", "Bearer " + bearerToken).asJson();

        if (response.hasNonNull("serviceErrorCode")) {
            throw new IdentityBrokerException("Could not obtain response from [" + url + "]. Response from server: " + response);
        }

        return response;
    }

    @Override
    protected String getDefaultScopes() {
        return DEFAULT_SCOPE;
    }
}
