/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.am.gateway.handler.vertx.auth.handler;

import io.gravitee.am.gateway.handler.oauth2.assertion.ClientAssertionService;
import io.gravitee.am.gateway.handler.oauth2.exception.InvalidClientException;
import io.gravitee.am.gateway.handler.oauth2.utils.OAuth2Constants;
import io.gravitee.am.model.Client;
import io.reactivex.Maybe;
import io.vertx.core.Handler;
import io.vertx.core.http.HttpMethod;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.AuthHandler;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;

/**
 * @author Alexandre FARIA (lusoalex at github.com)
 * @author GraviteeSource Team
 */
@RunWith(MockitoJUnitRunner.class)
public class ClientAssertionAuthHandlerTest extends GraviteeAuthHandlerTestBase {

    @Mock
    private ClientAssertionService clientAssertionService;

    private final static String CLIENT_ID = "my-client";
    private final static String CLIENT_SECRET = "my-secret";

    @Before
    public void setUpHandlerAndRouter() {
        Handler<RoutingContext> handler = rc -> {
            assertNotNull(rc.user());
            assertEquals(CLIENT_ID, rc.user().principal().getString(OAuth2Constants.CLIENT_ID));
            rc.response().end();
        };

        router.route("/token/*")
                .handler(ClientAssertionAuthHandler.create(new DummyAuthProvider(),clientAssertionService).getDelegate())
                .handler(handler);
    }

    @Test
    public void unauthorized_noCredentials() throws Exception {
        testRequest(HttpMethod.POST, "/token/", 401, "Unauthorized");
    }

    @Test
    public void unauthorized_invalidClient() throws Exception {
        when(clientAssertionService.assertClient(any(),any(),any())).thenReturn(Maybe.error(new InvalidClientException("Unknown or unsupported assertion_type")));
        testRequest(HttpMethod.POST, "/token?client_assertion_type=type&client_assertion=myToken", 401, "Unauthorized");
    }

    @Test
    public void unauthorized_clientDoesNotMatch() throws Exception {
        Client client = Mockito.mock(Client.class);
        when(client.getClientId()).thenReturn(CLIENT_ID);
        when(clientAssertionService.assertClient(any(),any(),any())).thenReturn(Maybe.just(client));

        testRequest(HttpMethod.POST, "/token?client_assertion_type=type&client_assertion=myToken&client_id=notMatching", 401, "Unauthorized");
    }

    @Test
    public void success() throws Exception {
        Client client = Mockito.mock(Client.class);
        when(client.getClientId()).thenReturn(CLIENT_ID);
        when(client.getClientSecret()).thenReturn(CLIENT_SECRET);
        when(clientAssertionService.assertClient(any(),any(),any())).thenReturn(Maybe.just(client));

        testRequest(HttpMethod.POST, "/token?client_assertion_type=type&client_assertion=myToken", 200, "OK");
    }

    @Override
    protected AuthHandler createAuthHandler(AuthProvider authProvider) {
        return ClientAssertionAuthHandler.create(authProvider,clientAssertionService).getDelegate();
    }


}
