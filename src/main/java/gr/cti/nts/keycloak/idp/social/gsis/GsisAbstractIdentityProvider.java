/*
 * Copyright 2021 Greek School Network and Networking Technologies Directorate (https://www.cti.gr/nts-department/),
 * Konstantinos Togias (ktogias@cti.gr) and/or their affiliates and other contributors as indicated
 * by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package gr.cti.nts.keycloak.idp.social.gsis;

import java.io.IOException;
import java.io.StringReader;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.util.Time;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.util.JsonSerialization;
import org.keycloak.vault.VaultStringSecret;
import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import gr.cti.nts.keycloak.idp.social.gsis.resource.GsisLogoutResource;
import gr.cti.nts.keycloak.idp.social.gsis.resource.GsisLogoutResourceProviderFactory;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;
import lombok.extern.jbosslog.JBossLog;

@JBossLog
public abstract class GsisAbstractIdentityProvider extends AbstractOAuth2IdentityProvider<OAuth2IdentityProviderConfig>
    implements SocialIdentityProvider<OAuth2IdentityProviderConfig> {

  public static final String FEDERATED_ID_TOKEN = "FEDERATED_ID_TOKEN";

  // Keycloak 22 creates the context from the user id and links the IdP through setIdpConfig() and
  // setIdp(). Newer versions take the IdentityProviderModel in the constructor and no longer have
  // setIdpConfig(). Resolve what is available once, so the same jar links on both.
  private static final List<Class<?>[]> CONTEXT_CONSTRUCTOR_SIGNATURES = List.of(
      new Class<?>[] {IdentityProviderModel.class},
      new Class<?>[] {String.class});

  private static final Constructor<BrokeredIdentityContext> CONTEXT_CONSTRUCTOR =
      findContextConstructor();
  private static final Method SET_IDP_CONFIG =
      findContextMethod("setIdpConfig", IdentityProviderModel.class);
  private static final Method SET_IDP = findContextMethod("setIdp", IdentityProvider.class);

  public GsisAbstractIdentityProvider(KeycloakSession session,
      OAuth2IdentityProviderConfig config) {
    super(session, config);
    config.setAuthorizationUrl(getAuthUrl());
    config.setTokenUrl(getTokenUrl());
  }

  protected abstract String getAuthUrl();

  protected abstract String getTokenUrl();

  protected abstract String getDefaultScope();

  protected abstract String getUserInfoUrl();

  protected abstract String getLogoutUrl();

  @Override
  public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
    return new OIDCEndpoint(callback, realm, event, this);
  }

  @Override
  protected boolean supportsExternalExchange() {
    return true;
  }

  private static Constructor<BrokeredIdentityContext> findContextConstructor() {
    for (Class<?>[] signature : CONTEXT_CONSTRUCTOR_SIGNATURES) {
      try {
        Constructor<BrokeredIdentityContext> constructor =
            BrokeredIdentityContext.class.getConstructor(signature);
        log.infof("Using %s", constructor);
        return constructor;
      } catch (NoSuchMethodException e) {
        // try the next one
      }
    }
    throw new IllegalStateException("No supported BrokeredIdentityContext constructor found");
  }

  private static Method findContextMethod(String name, Class<?> parameterType) {
    try {
      return BrokeredIdentityContext.class.getMethod(name, parameterType);
    } catch (NoSuchMethodException e) {
      return null;
    }
  }

  private BrokeredIdentityContext createBrokeredIdentityContext(String username,
      OAuth2IdentityProviderConfig config) {
    Object[] args = Arrays.stream(CONTEXT_CONSTRUCTOR.getParameterTypes())
        .map(type -> type == String.class ? username : config).toArray();

    try {
      BrokeredIdentityContext context = CONTEXT_CONSTRUCTOR.newInstance(args);
      if (SET_IDP_CONFIG != null) {
        SET_IDP_CONFIG.invoke(context, config);
      }
      if (SET_IDP != null) {
        SET_IDP.invoke(context, this);
      }
      return context;
    } catch (ReflectiveOperationException e) {
      throw new IdentityBrokerException(
          "Could not create BrokeredIdentityContext for user " + username, e);
    }
  }

  @Override
  protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event,
      JsonNode profile) {
    String username = getJsonProperty(profile, "userid");
    String firstname = getJsonProperty(profile, "firstname");
    String lastname = getJsonProperty(profile, "lastname");

    OAuth2IdentityProviderConfig config = getConfig();
    BrokeredIdentityContext user = createBrokeredIdentityContext(username, config);

    user.setId(username);
    user.setUsername(username);
    user.setFirstName(firstname);
    user.setLastName(lastname);
    user.setEmail("");

    AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, config.getAlias());

    return user;
  }

  @Override
  protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
    String profileUrl = getUserInfoUrl();
    String jsonStringProfile = "";

    try {
      String profile = SimpleHttpAdapter.doGet(profileUrl, session)
          .header("Authorization", "Bearer " + accessToken).asString();

      SAXParserFactory parserFactory = SAXParserFactory.newInstance();
      parserFactory.setValidating(false);
      parserFactory.setXIncludeAware(false);
      parserFactory.setNamespaceAware(false);

      final Map<String, String> userFields = new HashMap<String, String>();
      SAXParser parser = parserFactory.newSAXParser();

      parser.parse(new InputSource(new StringReader(profile)), new DefaultHandler() {
        @Override
        public void startElement(String uri, String localName, String qName, Attributes attributes)
            throws SAXException {
          if ("userinfo".equals(qName)) {
            userFields.put("userid", attributes.getValue("userid"));
            userFields.put("taxid", attributes.getValue("taxid"));
            userFields.put("lastname", attributes.getValue("lastname"));
            userFields.put("firstname", attributes.getValue("firstname"));
            userFields.put("fathername", attributes.getValue("fathername"));
            userFields.put("mothername", attributes.getValue("mothername"));
            userFields.put("birthyear", attributes.getValue("birthyear"));
          }
        }
      });

      jsonStringProfile += "{";

      int index = 0;
      for (Map.Entry<String, String> m : userFields.entrySet()) {
        if (index > 0) {
          jsonStringProfile += ", ";
        }
        jsonStringProfile += "\"" + m.getKey() + "\":\"" + m.getValue() + "\"";
        index++;
      }

      jsonStringProfile += "}";

      ObjectMapper mapper = new ObjectMapper();
      JsonNode jsonProfile = mapper.readTree(jsonStringProfile);

      return extractIdentityFromProfile(null, jsonProfile);
    } catch (Exception e) {
      throw new IdentityBrokerException(
          "Could not obtain user profile from gsis. *** Profile:" + jsonStringProfile + " ***", e);
    }
  }

  @Override
  protected String getDefaultScopes() {
    return getDefaultScope();
  }

  private String getIDTokenForLogout(KeycloakSession session, UserSessionModel userSession) {
    String tokenExpirationString = userSession.getNote(FEDERATED_TOKEN_EXPIRATION);
    long expirationTime = tokenExpirationString == null ? 0 : Long.parseLong(tokenExpirationString);
    int currentTime = Time.currentTime();

    if (expirationTime > 0 && currentTime > expirationTime) {
      String response = refreshTokenForLogout(session, userSession);
      AccessTokenResponse tokenResponse = null;

      try {
        tokenResponse = JsonSerialization.readValue(response, AccessTokenResponse.class);
      } catch (IOException e) {
        throw new RuntimeException(e);
      }

      return tokenResponse.getIdToken();
    }

    return userSession.getNote(FEDERATED_ID_TOKEN);
  }

  protected static class OIDCEndpoint extends Endpoint {
    public OIDCEndpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event,
        AbstractOAuth2IdentityProvider<OAuth2IdentityProviderConfig> provider) {
      super(callback, realm, event, provider);
    }
  }

  /**
   * Returns access token response as a string from a refresh token invocation on the remote OIDC
   * broker
   *
   * @param session
   * @param userSession
   * @return
   */
  public String refreshTokenForLogout(KeycloakSession session, UserSessionModel userSession) {
    String refreshToken = userSession.getNote(FEDERATED_REFRESH_TOKEN);
    OAuth2IdentityProviderConfig config = getConfig();
    String clientSecret = config.getClientSecret();

    try (VaultStringSecret vaultStringSecret = session.vault().getStringSecret(clientSecret)) {
      return buildRefreshTokenRequest(session, refreshToken, config.getClientId(),
          vaultStringSecret.get().orElse(clientSecret)).asString();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  // Not named getRefreshTokenRequest(), which Keycloak 26.4+ declares in the superclass with a
  // SimpleHttpRequest return type.
  protected SimpleHttpAdapter buildRefreshTokenRequest(KeycloakSession session,
      String refreshToken, String clientId, String clientSecret) {
    // authenticateTokenRequest() is typed to the version-specific SimpleHttp class, so send the
    // client credentials as form parameters (client_secret_post) instead.
    return SimpleHttpAdapter.doPost(getConfig().getTokenUrl(), session)
        .param(OAUTH2_GRANT_TYPE_REFRESH_TOKEN, refreshToken)
        .param(OAUTH2_PARAMETER_GRANT_TYPE, OAUTH2_GRANT_TYPE_REFRESH_TOKEN)
        .param(OAUTH2_PARAMETER_CLIENT_ID, clientId)
        .param(OAUTH2_PARAMETER_CLIENT_SECRET, clientSecret);
  }

  @Override
  public Response keycloakInitiatedBrowserLogout(KeycloakSession session,
      UserSessionModel userSession, UriInfo uriInfo, RealmModel realm) {
    String logoutUrl = getLogoutUrl();

    if (logoutUrl == null || logoutUrl.trim().isEmpty()) {
      return null;
    }

    log.infof("Initiating GSIS logout for user session: %s", userSession.getId());

    String idToken = getIDTokenForLogout(session, userSession);
    String sessionId = userSession.getId();
    UriBuilder logoutUri = UriBuilder.fromUri(logoutUrl).queryParam("state", sessionId);

    if (idToken != null) {
      logoutUri.queryParam("id_token_hint", idToken);
    }

    // GSIS redirects back to a RealmResourceProvider endpoint. A @Path method on OIDCEndpoint
    // (under /broker/{alias}/endpoint) is not routed by Keycloak 24+ for third-party providers.
    OAuth2IdentityProviderConfig config = getConfig();
    String redirect = UriBuilder.fromUri(uriInfo.getBaseUri())
        .path("realms").path(realm.getName())
        .path(GsisLogoutResourceProviderFactory.ID).path(GsisLogoutResource.LOGOUT_RESPONSE_PATH)
        .queryParam("state", sessionId).build().toString();
    logoutUri.queryParam("url", redirect);

    return Response.status(302).location(logoutUri.build(config.getClientId())).build();
  }
}
