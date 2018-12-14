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
package io.gravitee.am.gateway.handler.vertx.handler.oidc.handler;

import io.gravitee.am.gateway.handler.oauth2.client.ClientSyncService;
import io.gravitee.am.gateway.handler.oauth2.exception.InvalidTokenException;
import io.gravitee.am.gateway.handler.oauth2.token.impl.AccessToken;
import io.gravitee.am.gateway.handler.oidc.exception.ClientRegistrationDisabledException;
import io.gravitee.am.model.Client;
import io.gravitee.am.model.Domain;
import io.gravitee.am.model.oidc.OIDCSettings;
import io.gravitee.am.gateway.handler.oauth2.token.TokenService;
import io.gravitee.am.service.exception.ClientNotFoundException;
import io.reactivex.Maybe;
import io.vertx.reactivex.ext.web.RoutingContext;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

import java.util.Date;

import static org.mockito.Mockito.*;

/**
 * @author Alexandre FARIA (lusoalex at github.com)
 * @author GraviteeSource Team
 */
@RunWith(MockitoJUnitRunner.class)
public class DynamicClientRegistrationHandlerTest {

    private final static String DOMAIN = "domain-for-test";
    private final static String CLIENT = "client-for-test";

    @Test
    public void testWithNullOidcSettings() {
        Domain domain = Mockito.mock(Domain.class);
        RoutingContext rc = Mockito.mock(RoutingContext.class);

        ArgumentCaptor<Throwable> excecptionCaptor = ArgumentCaptor.forClass(Throwable.class);
        doNothing().when(rc).fail(excecptionCaptor.capture());

        DynamicClientRegistrationHandler handler = new DynamicClientRegistrationHandler(domain, null, null);
        handler.handle(rc);

        Assert.assertTrue("Should return a DCR disabled exception", excecptionCaptor.getValue() instanceof ClientRegistrationDisabledException);
    }

    @Test
    public void testWithOidcDcrDisabled() {
        OIDCSettings disabled = OIDCSettings.defaultSettings();
        disabled.getClientRegistrationSettings().setDynamicClientRegistrationEnabled(false);

        Domain domain = Mockito.mock(Domain.class);
        when(domain.getOidc()).thenReturn(disabled);

        RoutingContext rc = Mockito.mock(RoutingContext.class);

        DynamicClientRegistrationHandler handler = new DynamicClientRegistrationHandler(domain, null, null);
        handler.handle(rc);

        ArgumentCaptor<Throwable> excecptionCaptor = ArgumentCaptor.forClass(Throwable.class);
        verify(rc, times(1)).fail(excecptionCaptor.capture());
        Assert.assertTrue("Should return a DCR disabled exception", excecptionCaptor.getValue() instanceof ClientRegistrationDisabledException);
    }


    @Test
    public void testWithOidcDcrEnabled_openDcrEnabled() {
        OIDCSettings openDcr = OIDCSettings.defaultSettings();
        openDcr.getClientRegistrationSettings().setDynamicClientRegistrationEnabled(true);
        openDcr.getClientRegistrationSettings().setOpenDynamicClientRegistrationEnabled(true);

        Domain domain = Mockito.mock(Domain.class);
        when(domain.getOidc()).thenReturn(openDcr);

        RoutingContext rc = Mockito.mock(RoutingContext.class);

        DynamicClientRegistrationHandler handler = new DynamicClientRegistrationHandler(domain, null, null);
        handler.handle(rc);

        ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);
        verify(rc, times(1)).put(keyCaptor.capture(), any());
        Assert.assertTrue("Should put the domain in context", keyCaptor.getValue().equals("domain"));
        verify(rc, times(1)).next();
    }

    @Test
    public void testWithOidcDcrEnabled_notAuthenticated() {
        OIDCSettings openDcr = OIDCSettings.defaultSettings();
        openDcr.getClientRegistrationSettings().setDynamicClientRegistrationEnabled(true);
        openDcr.getClientRegistrationSettings().setOpenDynamicClientRegistrationEnabled(false);

        Domain domain = Mockito.mock(Domain.class);
        when(domain.getOidc()).thenReturn(openDcr);

        TokenService tokenService = Mockito.mock(TokenService.class);
        when(tokenService.extractAccessToken(any(),eq(false))).thenReturn(Maybe.empty());

        RoutingContext rc = Mockito.mock(RoutingContext.class);

        DynamicClientRegistrationHandler handler = new DynamicClientRegistrationHandler(domain, tokenService, null);
        handler.handle(rc);

        ArgumentCaptor<Throwable> excecptionCaptor = ArgumentCaptor.forClass(Throwable.class);
        verify(rc, times(1)).fail(excecptionCaptor.capture());
        Assert.assertTrue("Should return a DCR disabled exception", excecptionCaptor.getValue() instanceof ClientRegistrationDisabledException);
    }

    @Test
    public void testWithOidcDcrEnabled_authenticatedButTokenExpired() {
        OIDCSettings openDcr = OIDCSettings.defaultSettings();
        openDcr.getClientRegistrationSettings().setDynamicClientRegistrationEnabled(true);
        openDcr.getClientRegistrationSettings().setOpenDynamicClientRegistrationEnabled(false);

        Domain domain = Mockito.mock(Domain.class);
        when(domain.getOidc()).thenReturn(openDcr);

        AccessToken token = Mockito.mock(AccessToken.class);
        when(token.getExpireAt()).thenReturn(Date.from(new Date().toInstant().minusSeconds(3600)));

        TokenService tokenService = Mockito.mock(TokenService.class);
        when(tokenService.extractAccessToken(any(),eq(false))).thenReturn(Maybe.just(token));
        when(tokenService.getAccessToken(any(),any())).thenReturn(Maybe.just(token));

        ClientSyncService clientSyncService = Mockito.mock(ClientSyncService.class);
        when(clientSyncService.findByClientId(any())).thenReturn(Maybe.just(new Client()));

        RoutingContext rc = Mockito.mock(RoutingContext.class);

        DynamicClientRegistrationHandler handler = new DynamicClientRegistrationHandler(domain, tokenService, clientSyncService);
        handler.handle(rc);

        ArgumentCaptor<Throwable> excecptionCaptor = ArgumentCaptor.forClass(Throwable.class);
        verify(rc, times(1)).fail(excecptionCaptor.capture());
        Assert.assertTrue("Should return a DCR disabled exception", excecptionCaptor.getValue() instanceof InvalidTokenException);
    }

    @Test
    public void testWithOidcDcrEnabled_authenticatedButClientNotFound() {
        OIDCSettings openDcr = OIDCSettings.defaultSettings();
        openDcr.getClientRegistrationSettings().setDynamicClientRegistrationEnabled(true);
        openDcr.getClientRegistrationSettings().setOpenDynamicClientRegistrationEnabled(false);

        Domain domain = Mockito.mock(Domain.class);
        when(domain.getOidc()).thenReturn(openDcr);
        when(domain.getId()).thenReturn(DOMAIN);

        AccessToken token = Mockito.mock(AccessToken.class);
        when(token.getExpireAt()).thenReturn(Date.from(new Date().toInstant().plusSeconds(3600)));
        when(token.getClientId()).thenReturn(CLIENT);

        TokenService tokenService = Mockito.mock(TokenService.class);
        when(tokenService.extractAccessToken(any(),eq(false))).thenReturn(Maybe.just(token));
        when(tokenService.getAccessToken(any(),any())).thenReturn(Maybe.just(token));

        ClientSyncService clientSyncService = Mockito.mock(ClientSyncService.class);
        when(clientSyncService.findByClientId(any())).thenReturn(Maybe.empty());

        RoutingContext rc = Mockito.mock(RoutingContext.class);

        DynamicClientRegistrationHandler handler = new DynamicClientRegistrationHandler(domain, tokenService, clientSyncService);
        handler.handle(rc);

        ArgumentCaptor<Throwable> excecptionCaptor = ArgumentCaptor.forClass(Throwable.class);
        verify(rc, times(1)).fail(excecptionCaptor.capture());
        System.out.println( excecptionCaptor.getValue());
        Assert.assertTrue("Should return a Client not found exception", excecptionCaptor.getValue() instanceof ClientNotFoundException);
    }

    @Test
    public void testWithOidcDcrEnabled_authenticatedButClientDcrDisabled() {
        OIDCSettings openDcr = OIDCSettings.defaultSettings();
        openDcr.getClientRegistrationSettings().setDynamicClientRegistrationEnabled(true);
        openDcr.getClientRegistrationSettings().setOpenDynamicClientRegistrationEnabled(false);

        Domain domain = Mockito.mock(Domain.class);
        when(domain.getOidc()).thenReturn(openDcr);
        when(domain.getId()).thenReturn(DOMAIN);

        AccessToken token = Mockito.mock(AccessToken.class);
        when(token.getExpireAt()).thenReturn(Date.from(new Date().toInstant().plusSeconds(3600)));
        when(token.getClientId()).thenReturn(CLIENT);

        TokenService tokenService = Mockito.mock(TokenService.class);
        when(tokenService.extractAccessToken(any(),eq(false))).thenReturn(Maybe.just(token));
        when(tokenService.getAccessToken(any(),any())).thenReturn(Maybe.just(token));

        ClientSyncService clientSyncService = Mockito.mock(ClientSyncService.class);
        when(clientSyncService.findByClientId(any())).thenReturn(Maybe.just(new Client()));

        RoutingContext rc = Mockito.mock(RoutingContext.class);

        DynamicClientRegistrationHandler handler = new DynamicClientRegistrationHandler(domain, tokenService, clientSyncService);
        handler.handle(rc);

        ArgumentCaptor<Throwable> excecptionCaptor = ArgumentCaptor.forClass(Throwable.class);
        verify(rc, times(1)).fail(excecptionCaptor.capture());
        System.out.println( excecptionCaptor.getValue());
        Assert.assertTrue("Should return a DCR disabled exception", excecptionCaptor.getValue() instanceof ClientRegistrationDisabledException);
    }

    @Test
    public void testWithOidcDcrEnabled_authenticatedAndClientDcrEnabled() {
        OIDCSettings openDcr = OIDCSettings.defaultSettings();
        openDcr.getClientRegistrationSettings().setDynamicClientRegistrationEnabled(true);
        openDcr.getClientRegistrationSettings().setOpenDynamicClientRegistrationEnabled(false);

        Domain domain = Mockito.mock(Domain.class);
        when(domain.getOidc()).thenReturn(openDcr);
        when(domain.getId()).thenReturn(DOMAIN);

        AccessToken token = Mockito.mock(AccessToken.class);
        when(token.getExpireAt()).thenReturn(Date.from(new Date().toInstant().plusSeconds(3600)));
        when(token.getClientId()).thenReturn(CLIENT);

        TokenService tokenService = Mockito.mock(TokenService.class);
        when(tokenService.extractAccessToken(any(),eq(false))).thenReturn(Maybe.just(token));
        when(tokenService.getAccessToken(any(),any())).thenReturn(Maybe.just(token));

        Client client = Mockito.mock(Client.class);
        when(client.isDynamicClientRegistrationEnabled()).thenReturn(true);

        ClientSyncService clientSyncService = Mockito.mock(ClientSyncService.class);
        when(clientSyncService.findByClientId(any())).thenReturn(Maybe.just(client));

        RoutingContext rc = Mockito.mock(RoutingContext.class);

        DynamicClientRegistrationHandler handler = new DynamicClientRegistrationHandler(domain, tokenService, clientSyncService);
        handler.handle(rc);

        ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);
        verify(rc, times(2)).put(keyCaptor.capture(), any());
        Assert.assertTrue("Should put the domain in context", keyCaptor.getValue().equals("domain"));
        verify(rc, times(1)).next();
    }
}
