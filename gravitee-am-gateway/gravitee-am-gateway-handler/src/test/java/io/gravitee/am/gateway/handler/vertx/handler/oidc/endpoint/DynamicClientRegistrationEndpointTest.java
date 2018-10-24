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
package io.gravitee.am.gateway.handler.vertx.handler.oidc.endpoint;

import io.gravitee.am.gateway.handler.oauth2.client.ClientSyncService;
import io.gravitee.am.gateway.handler.oidc.clientregistration.DynamicClientRegistrationService;
import io.gravitee.am.gateway.handler.oidc.request.DynamicClientRegistrationRequest;
import io.gravitee.am.model.Client;
import io.gravitee.am.service.ClientService;
import io.reactivex.Single;
import io.vertx.reactivex.core.http.HttpServerResponse;
import io.vertx.core.json.JsonObject;
import io.vertx.reactivex.ext.web.RoutingContext;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

import static org.mockito.Mockito.*;

/**
 * @author Alexandre FARIA (lusoalex at github.com)
 * @author GraviteeSource Team
 */
@RunWith(MockitoJUnitRunner.class)
public class DynamicClientRegistrationEndpointTest {

    @Mock
    private ClientService clientService;

    @Mock
    private ClientSyncService clientSyncService;

    @Mock
    private DynamicClientRegistrationService dcrService;

    @Test
    public void handle_invalidRequest() {
        //Mock
        DynamicClientRegistrationRequest request = Mockito.mock(DynamicClientRegistrationRequest.class);
        JsonObject json = Mockito.mock(JsonObject.class);
        RoutingContext rc = Mockito.mock(RoutingContext.class);

        when(json.mapTo(DynamicClientRegistrationRequest.class)).thenReturn(request);
        when(rc.get("domain")).thenReturn("domain-for-test");
        when(rc.getBodyAsJson()).thenReturn(json);

        when(dcrService.validateClientRequest(any())).thenReturn(Single.error(new Exception()));

        //Test
        DynamicClientRegistrationEndpoint endpoint = new DynamicClientRegistrationEndpoint(dcrService, clientService, clientSyncService);
        endpoint.handle(rc);

        //Assertions
        verify(rc, times(1)).fail(any());
    }

    @Test
    public void handle_createFail() {
        //Mocks
        DynamicClientRegistrationRequest request = Mockito.mock(DynamicClientRegistrationRequest.class);
        JsonObject json = Mockito.mock(JsonObject.class);
        RoutingContext rc = Mockito.mock(RoutingContext.class);

        when(rc.get("domain")).thenReturn("domain-for-test");
        when(rc.getBodyAsJson()).thenReturn(json);
        when(json.mapTo(DynamicClientRegistrationRequest.class)).thenReturn(request);
        when(request.patch(any())).thenReturn(new Client());

        when(dcrService.validateClientRequest(any())).thenReturn(Single.just(request));
        when(clientService.create(any(),(Client)any())).thenReturn(Single.error(new Exception()));

        //Test
        DynamicClientRegistrationEndpoint endpoint = new DynamicClientRegistrationEndpoint(dcrService, clientService, clientSyncService);
        endpoint.handle(rc);

        //Assertions
        verify(rc, times(1)).fail(any());
    }

    @Test
    public void handle_success() {
        //Mocks
        DynamicClientRegistrationRequest request = Mockito.mock(DynamicClientRegistrationRequest.class);
        JsonObject json = Mockito.mock(JsonObject.class);
        RoutingContext rc = Mockito.mock(RoutingContext.class);
        HttpServerResponse response = Mockito.mock(HttpServerResponse.class);

        when(rc.get("domain")).thenReturn("domain-for-test");
        when(rc.getBodyAsJson()).thenReturn(json);
        when(json.mapTo(DynamicClientRegistrationRequest.class)).thenReturn(request);
        when(request.patch(any())).thenReturn(new Client());
        when(response.putHeader(anyString(),anyString())).thenReturn(response);
        when(rc.response()).thenReturn(response);

        when(dcrService.validateClientRequest(any())).thenReturn(Single.just(request));
        when(dcrService.applyDefaultIdentityProvider(any(),any())).thenReturn(Single.just(new Client()));
        when(dcrService.applyDefaultCertificateProvider(any(),any())).thenReturn(Single.just(new Client()));
        when(clientService.create(any(),(Client)any())).thenReturn(Single.just(new Client()));
        when(clientSyncService.addDynamicClientRegistred(any())).thenReturn(new Client());

        //Test
        DynamicClientRegistrationEndpoint endpoint = new DynamicClientRegistrationEndpoint(dcrService, clientService, clientSyncService);
        endpoint.handle(rc);

        verify(rc, times(1)).response();
        verify(response,times(3)).putHeader(anyString(),anyString());
        verify(response,times(1)).end(anyString());
    }
}
