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

package gr.cti.nts.keycloak.idp.social.gsis.resource;

import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;

/**
 * Finishes the Keycloak side of a logout after GSIS redirects back to
 * {@code /realms/{realm}/gsis-logout/response}.
 */

@JBossLog
public class GsisLogoutResource {

  public static final String LOGOUT_RESPONSE_PATH = "response";

  private final KeycloakSession session;

  public GsisLogoutResource(KeycloakSession session) {
    this.session = session;
  }

  @GET
  @Path(LOGOUT_RESPONSE_PATH)
  public Response logoutResponse(@QueryParam("state") String state) {
    RealmModel realm = session.getContext().getRealm();

    if (state == null) {
      log.error("no state parameter returned");
      EventBuilder event = new EventBuilder(realm, session, session.getContext().getConnection());
      event.event(EventType.LOGOUT);
      event.error(Errors.USER_SESSION_NOT_FOUND);

      return ErrorPage.error(session, null, Response.Status.BAD_REQUEST,
          Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
    }

    UserSessionModel userSession = session.sessions().getUserSession(realm, state);
    if (userSession == null) {
      log.error("no valid user session");
      EventBuilder event = new EventBuilder(realm, session, session.getContext().getConnection());
      event.event(EventType.LOGOUT);
      event.error(Errors.USER_SESSION_NOT_FOUND);

      return ErrorPage.error(session, null, Response.Status.BAD_REQUEST,
          Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
    }

    if (userSession.getState() != UserSessionModel.State.LOGGING_OUT) {
      log.error("usersession in different state");
      EventBuilder event = new EventBuilder(realm, session, session.getContext().getConnection());
      event.event(EventType.LOGOUT);
      event.error(Errors.USER_SESSION_NOT_FOUND);

      return ErrorPage.error(session, null, Response.Status.BAD_REQUEST,
          Messages.SESSION_NOT_ACTIVE);
    }

    return AuthenticationManager.finishBrowserLogout(session, realm, userSession,
        session.getContext().getUri(), session.getContext().getConnection(),
        session.getContext().getRequestHeaders());
  }
}
