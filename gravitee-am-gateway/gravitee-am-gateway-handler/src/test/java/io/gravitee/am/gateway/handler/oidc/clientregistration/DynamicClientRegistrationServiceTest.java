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
package io.gravitee.am.gateway.handler.oidc.clientregistration;

import io.gravitee.am.gateway.handler.jwk.JwkService;
import io.gravitee.am.gateway.handler.oidc.clientregistration.impl.DynamicClientRegistrationServiceImpl;
import io.gravitee.am.gateway.handler.oidc.request.DynamicClientRegistrationRequest;
import io.gravitee.am.model.Certificate;
import io.gravitee.am.model.Client;
import io.gravitee.am.model.IdentityProvider;
import io.gravitee.am.model.oidc.JWKSet;
import io.gravitee.am.service.CertificateService;
import io.gravitee.am.service.GrantTypeService;
import io.gravitee.am.service.IdentityProviderService;
import io.gravitee.am.service.ResponseTypeService;
import io.gravitee.am.service.exception.InvalidClientMetadataException;
import io.gravitee.am.service.exception.InvalidRedirectUriException;
import io.reactivex.Maybe;
import io.reactivex.Single;
import io.reactivex.observers.TestObserver;
import io.vertx.reactivex.core.buffer.Buffer;
import io.vertx.reactivex.ext.web.client.HttpRequest;
import io.vertx.reactivex.ext.web.client.HttpResponse;
import io.vertx.reactivex.ext.web.client.WebClient;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

/**
 * @author Alexandre FARIA (lusoalex at github.com)
 * @author GraviteeSource Team
 */
@RunWith(MockitoJUnitRunner.class)
public class DynamicClientRegistrationServiceTest {

    @InjectMocks
    private DynamicClientRegistrationService dcrService = new DynamicClientRegistrationServiceImpl();

    @Mock
    private GrantTypeService grantTypeService;

    @Mock
    private ResponseTypeService responseTypeService;

    @Mock
    private IdentityProviderService identityProviderService;

    @Mock
    private CertificateService certificateService;

    @Mock
    private JwkService jwkService;

    @Mock
    public WebClient webClient;

    @Test
    public void applyDefaultIdentiyProvider_noIdentityProvider() {
        when(identityProviderService.findByDomain(any())).thenReturn(Single.just(Collections.emptyList()));

        TestObserver testObserver = dcrService.applyDefaultIdentityProvider("domain",new Client()).test();
        testObserver.assertNoErrors();
        testObserver.assertComplete();
        testObserver.assertValue(client -> client!=null & ((Client)client).getIdentities()==null);
    }

    @Test
    public void applyDefaultIdentiyProvider() {
        IdentityProvider identityProvider = Mockito.mock(IdentityProvider.class);
        when(identityProvider.getId()).thenReturn("identity-provider-id-123");

        when(identityProviderService.findByDomain(any())).thenReturn(Single.just(Arrays.asList(identityProvider)));

        TestObserver testObserver = dcrService.applyDefaultIdentityProvider("domain",new Client()).test();
        testObserver.assertNoErrors();
        testObserver.assertComplete();
        testObserver.assertValue(client -> client!=null & ((Client)client).getIdentities().contains("identity-provider-id-123"));
    }

    @Test
    public void applyDefaultCertificateProvider_noCertificateProvider() {
        when(certificateService.findByDomain(any())).thenReturn(Single.just(Collections.emptyList()));

        TestObserver testObserver = dcrService.applyDefaultCertificateProvider("domain",new Client()).test();
        testObserver.assertNoErrors();
        testObserver.assertComplete();
        testObserver.assertValue(client -> client!=null & ((Client)client).getCertificate()==null);
    }

    @Test
    public void applyDefaultCertificateProvider_default() {
        Certificate certificate = Mockito.mock(Certificate.class);
        when(certificate.getId()).thenReturn("certificate-id-123");

        when(certificateService.findByDomain(any())).thenReturn(Single.just(Arrays.asList(certificate)));

        TestObserver testObserver = dcrService.applyDefaultCertificateProvider("domain",new Client()).test();
        testObserver.assertNoErrors();
        testObserver.assertComplete();
        testObserver.assertValue(client -> client!=null & ((Client)client).getCertificate().equals("certificate-id-123"));
    }

    @Test
    public void validateClientRequest_nullRequest() {
        TestObserver testObserver = dcrService.validateClientRequest(null).test();
        testObserver.assertError(InvalidClientMetadataException.class);
        testObserver.assertNotComplete();
    }

    @Test
    public void validateClientRequest_nullRedirectUriRequest() {
        TestObserver testObserver = dcrService.validateClientRequest(new DynamicClientRegistrationRequest()).test();
        testObserver.assertError(InvalidRedirectUriException.class);
        testObserver.assertNotComplete();
    }

    @Test
    public void validateClientRequest_emptyRedirectUriRequest() {
        DynamicClientRegistrationRequest request = new DynamicClientRegistrationRequest();
        request.setRedirectUris(Optional.empty());

        TestObserver testObserver = dcrService.validateClientRequest(request).test();
        testObserver.assertError(InvalidRedirectUriException.class);
        testObserver.assertNotComplete();
    }

    @Test
    public void validateClientRequest_emptyArrayRedirectUriRequest() {
        DynamicClientRegistrationRequest request = new DynamicClientRegistrationRequest();
        request.setRedirectUris(Optional.of(Arrays.asList()));

        TestObserver testObserver = dcrService.validateClientRequest(request).test();
        testObserver.assertError(InvalidRedirectUriException.class);
        testObserver.assertNotComplete();
    }


    @Test
    public void validateClientRequest_unknownResponseTypePayload() {
        DynamicClientRegistrationRequest request = new DynamicClientRegistrationRequest();
        request.setRedirectUris(Optional.of(Arrays.asList("https://graviee.io/callback")));
        request.setResponseTypes(Optional.of(Arrays.asList("unknownResponseType")));
        when(responseTypeService.isValideResponseType((List)any())).thenReturn(false);

        TestObserver testObserver = dcrService.validateClientRequest(request).test();
        testObserver.assertError(InvalidClientMetadataException.class);
        testObserver.assertNotComplete();
    }

    @Test
    public void validateClientRequest_unknownGrantTypePayload() {
        DynamicClientRegistrationRequest request = new DynamicClientRegistrationRequest();
        request.setRedirectUris(Optional.of(Arrays.asList("https://graviee.io/callback")));
        request.setGrantTypes(Optional.of(Arrays.asList("unknownGrantType")));

        when(grantTypeService.isValideGrantType((List)any())).thenReturn(false);

        TestObserver testObserver = dcrService.validateClientRequest(request).test();
        testObserver.assertError(InvalidClientMetadataException.class);
        testObserver.assertNotComplete();
    }

    @Test
    public void validateClientRequest_unvalidRequestUris() {
        DynamicClientRegistrationRequest request = new DynamicClientRegistrationRequest();
        request.setRedirectUris(Optional.of(Arrays.asList("https://graviee.io/callback")));
        request.setRequestUris(Optional.of(Arrays.asList("nonValidUri")));

        TestObserver testObserver = dcrService.validateClientRequest(request).test();
        testObserver.assertError(InvalidClientMetadataException.class);
        testObserver.assertNotComplete();
    }

    @Test
    public void validateClientRequest_validRequestUris() {
        DynamicClientRegistrationRequest request = new DynamicClientRegistrationRequest();
        request.setRedirectUris(Optional.of(Arrays.asList("https://graviee.io/callback")));
        request.setRequestUris(Optional.of(Arrays.asList("https://valid/request/uri")));

        TestObserver testObserver = dcrService.validateClientRequest(request).test();
        testObserver.assertNoErrors();
        testObserver.assertComplete();
    }


    @Test
    public void validateClientRequest_sectorIdentifierUriBadFormat() {
        DynamicClientRegistrationRequest request = new DynamicClientRegistrationRequest();
        request.setRedirectUris(Optional.of(Arrays.asList("https://graviee.io/callback")));
        request.setSectorIdentifierUri(Optional.of("blabla"));//fail due to invalid url

        TestObserver<DynamicClientRegistrationRequest> testObserver = dcrService.validateClientRequest(request).test();
        testObserver.assertError(InvalidClientMetadataException.class);
        testObserver.assertNotComplete();
    }

    @Test
    public void validateClientRequest_sectorIdentifierUriNottHttps() {
        DynamicClientRegistrationRequest request = new DynamicClientRegistrationRequest();
        request.setRedirectUris(Optional.of(Arrays.asList("https://graviee.io/callback")));
        request.setSectorIdentifierUri(Optional.of("http://something"));//fail due to invalid url

        TestObserver<DynamicClientRegistrationRequest> testObserver = dcrService.validateClientRequest(request).test();
        testObserver.assertError(InvalidClientMetadataException.class);
        testObserver.assertNotComplete();
    }

    @Test
    public void validateClientRequest_sectorIdentifierUriBadRequest() {
        final String sectorUri = "https://sector/uri";
        DynamicClientRegistrationRequest request = new DynamicClientRegistrationRequest();
        request.setRedirectUris(Optional.of(Arrays.asList("https://graviee.io/callback")));
        request.setSectorIdentifierUri(Optional.of(sectorUri));//fail due to invalid url
        HttpRequest<Buffer> httpRequest = Mockito.mock(HttpRequest.class);
        HttpResponse httpResponse = Mockito.mock(HttpResponse.class);

        when(webClient.getAbs(sectorUri)).thenReturn(httpRequest);
        when(httpRequest.rxSend()).thenReturn(Single.just(httpResponse));
        when(httpResponse.statusCode()).thenReturn(400);

        TestObserver<DynamicClientRegistrationRequest> testObserver = dcrService.validateClientRequest(request).test();
        testObserver.assertError(InvalidClientMetadataException.class);
        testObserver.assertNotComplete();
    }

    @Test
    public void validateClientRequest_sectorIdentifierUri_invalidRedirectUri() {
        final String sectorUri = "https://sector/uri";
        DynamicClientRegistrationRequest request = new DynamicClientRegistrationRequest();
        request.setRedirectUris(Optional.of(Arrays.asList("https://graviee.io/callback")));
        request.setSectorIdentifierUri(Optional.of(sectorUri));//fail due to invalid url
        HttpRequest<Buffer> httpRequest = Mockito.mock(HttpRequest.class);
        HttpResponse httpResponse = Mockito.mock(HttpResponse.class);

        when(webClient.getAbs(sectorUri)).thenReturn(httpRequest);
        when(httpRequest.rxSend()).thenReturn(Single.just(httpResponse));
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.bodyAsString()).thenReturn("[\"https://not/same/redirect/uri\"]");

        TestObserver<DynamicClientRegistrationRequest> testObserver = dcrService.validateClientRequest(request).test();
        testObserver.assertError(InvalidRedirectUriException.class);
        testObserver.assertNotComplete();
    }

    @Test
    public void validateClientRequest_sectorIdentifierUri_validRedirectUri() {
        final String redirectUri = "https://graviee.io/callback";
        final String sectorUri = "https://sector/uri";
        DynamicClientRegistrationRequest request = new DynamicClientRegistrationRequest();
        request.setRedirectUris(Optional.of(Arrays.asList(redirectUri)));
        request.setSectorIdentifierUri(Optional.of(sectorUri));//fail due to invalid url
        HttpRequest<Buffer> httpRequest = Mockito.mock(HttpRequest.class);
        HttpResponse httpResponse = Mockito.mock(HttpResponse.class);

        when(webClient.getAbs(sectorUri)).thenReturn(httpRequest);
        when(httpRequest.rxSend()).thenReturn(Single.just(httpResponse));
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.bodyAsString()).thenReturn("[\""+redirectUri+"\"]");

        TestObserver<DynamicClientRegistrationRequest> testObserver = dcrService.validateClientRequest(request).test();
        testObserver.assertNoErrors();
        testObserver.assertComplete();
    }

    @Test
    public void validateClientRequest_validateJWKsDuplicatedSource() {
        DynamicClientRegistrationRequest request = new DynamicClientRegistrationRequest();
        request.setRedirectUris(Optional.of(Arrays.asList("https://graviee.io/callback")));
        request.setJwks(Optional.of(new JWKSet()));
        request.setJwksUri(Optional.of("something"));

        TestObserver<DynamicClientRegistrationRequest> testObserver = dcrService.validateClientRequest(request).test();
        testObserver.assertError(InvalidClientMetadataException.class);
        testObserver.assertNotComplete();
    }

    @Test
    public void validateClientRequest_validateJWKsUriWithoutJwkSet() {
        DynamicClientRegistrationRequest request = new DynamicClientRegistrationRequest();
        request.setRedirectUris(Optional.of(Arrays.asList("https://graviee.io/callback")));
        request.setJwksUri(Optional.of("something"));

        when(jwkService.getKeys(any())).thenReturn(Maybe.empty());

        TestObserver<DynamicClientRegistrationRequest> testObserver = dcrService.validateClientRequest(request).test();
        testObserver.assertError(InvalidClientMetadataException.class);
        testObserver.assertNotComplete();
    }

    @Test
    public void validateClientRequest_validateJWKsUriOk() {
        DynamicClientRegistrationRequest request = new DynamicClientRegistrationRequest();
        request.setRedirectUris(Optional.of(Arrays.asList("https://graviee.io/callback")));
        request.setJwksUri(Optional.of("something"));

        when(jwkService.getKeys(any())).thenReturn(Maybe.just(new JWKSet()));

        TestObserver<DynamicClientRegistrationRequest> testObserver = dcrService.validateClientRequest(request).test();
        testObserver.assertNoErrors();
        testObserver.assertComplete();
    }

    @Test
    public void validateClientRequest_validateScope_noOpenidScopeRequested() {
        DynamicClientRegistrationRequest request = new DynamicClientRegistrationRequest();
        request.setRedirectUris(Optional.of(Arrays.asList("https://graviee.io/callback")));
        request.setScope(Optional.of("scope1 test"));

        TestObserver<DynamicClientRegistrationRequest> testObserver = dcrService.validateClientRequest(request).test();
        testObserver.assertNoErrors();
        testObserver.assertComplete();
        testObserver.assertValue(req -> req!=null && req.getScope().get().contains("openid"));
    }

    @Test
    public void validateClientRequest_ok() {
        DynamicClientRegistrationRequest request = new DynamicClientRegistrationRequest();
        request.setRedirectUris(Optional.of(Arrays.asList("https://graviee.io/callback")));

        TestObserver<DynamicClientRegistrationRequest> testObserver = dcrService.validateClientRequest(request).test();
        testObserver.assertNoErrors();
        testObserver.assertComplete();
    }
}
