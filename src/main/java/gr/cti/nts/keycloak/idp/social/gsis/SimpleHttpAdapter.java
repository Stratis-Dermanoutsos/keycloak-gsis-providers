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
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.keycloak.models.KeycloakSession;
import lombok.extern.jbosslog.JBossLog;

/**
 * Runtime bridge over the two SimpleHttp APIs, so that a single jar works on every supported
 * Keycloak version:
 *
 * <ul>
 * <li>Legacy: {@code org.keycloak.broker.provider.util.SimpleHttp.doGet(url, session)}</li>
 * <li>Current: {@code org.keycloak.http.simple.SimpleHttp.create(session).doGet(url)}</li>
 * </ul>
 *
 * The current API is preferred when both are present.
 */
@JBossLog
public class SimpleHttpAdapter {

  private static final String LEGACY_CLASS = "org.keycloak.broker.provider.util.SimpleHttp";
  private static final String CURRENT_CLASS = "org.keycloak.http.simple.SimpleHttp";

  // SimpleHttp.create(session), only on the current API
  private static final Method CREATE;
  private static final Method DO_GET;
  private static final Method DO_POST;

  static {
    Method create = null;
    Method doGet;
    Method doPost;

    try {
      Class<?> httpClass = Class.forName(CURRENT_CLASS);
      create = httpClass.getMethod("create", KeycloakSession.class);
      doGet = httpClass.getMethod("doGet", String.class);
      doPost = httpClass.getMethod("doPost", String.class);
    } catch (ClassNotFoundException e) {
      try {
        Class<?> httpClass = Class.forName(LEGACY_CLASS);
        doGet = httpClass.getMethod("doGet", String.class, KeycloakSession.class);
        doPost = httpClass.getMethod("doPost", String.class, KeycloakSession.class);
      } catch (ReflectiveOperationException ex) {
        throw new ExceptionInInitializerError(ex);
      }
    } catch (NoSuchMethodException e) {
      throw new ExceptionInInitializerError(e);
    }

    CREATE = create;
    DO_GET = doGet;
    DO_POST = doPost;
    log.infof("Using SimpleHttp API %s", DO_GET.getDeclaringClass().getName());
  }

  private Object request;

  private SimpleHttpAdapter(Object request) {
    this.request = request;
  }

  public static SimpleHttpAdapter doGet(String url, KeycloakSession session) {
    return new SimpleHttpAdapter(open(DO_GET, url, session));
  }

  public static SimpleHttpAdapter doPost(String url, KeycloakSession session) {
    return new SimpleHttpAdapter(open(DO_POST, url, session));
  }

  private static Object open(Method method, String url, KeycloakSession session) {
    try {
      if (CREATE != null) {
        return method.invoke(CREATE.invoke(null, session), url);
      }
      return method.invoke(null, url, session);
    } catch (ReflectiveOperationException e) {
      throw new RuntimeException("Failed to create request for URL: " + url, e);
    }
  }

  public SimpleHttpAdapter header(String name, String value) {
    request = invoke("header", name, value);
    return this;
  }

  public SimpleHttpAdapter param(String name, String value) {
    request = invoke("param", name, value);
    return this;
  }

  public String asString() throws IOException {
    try {
      return (String) request.getClass().getMethod("asString").invoke(request);
    } catch (InvocationTargetException e) {
      if (e.getCause() instanceof IOException ioException) {
        throw ioException;
      }
      throw new RuntimeException("Failed to execute request", e.getCause());
    } catch (ReflectiveOperationException e) {
      throw new RuntimeException("Failed to execute request", e);
    }
  }

  private Object invoke(String methodName, String name, String value) {
    try {
      return request.getClass().getMethod(methodName, String.class, String.class)
          .invoke(request, name, value);
    } catch (ReflectiveOperationException e) {
      throw new RuntimeException("Failed to call SimpleHttp." + methodName, e);
    }
  }
}
