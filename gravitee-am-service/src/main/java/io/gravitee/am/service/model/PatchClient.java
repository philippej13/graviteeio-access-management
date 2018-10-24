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
package io.gravitee.am.service.model;

import io.gravitee.am.model.Client;
import io.gravitee.am.service.utils.SetterUtils;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * @author Alexandre FARIA (lusoalex at github.com)
 * @author GraviteeSource Team
 */
public class PatchClient {

    private Optional<List<String>> redirectUris;
    private Optional<List<String>> grantTypes;
    private Optional<String> clientName;
    private Optional<List<String>> scope;
    private Optional<List<String>> autoApproveScopes;
    private Optional<Integer> accessTokenValiditySeconds;
    private Optional<Integer> refreshTokenValiditySeconds;
    private Optional<Integer> idTokenValiditySeconds;
    private Optional<Map<String, Object>> idTokenCustomClaims;
    private Optional<Boolean> enabled;
    private Optional<Set<String>> identities;
    private Optional<Set<String>> oauth2Identities;
    private Optional<String> certificate;
    private Optional<Boolean> enhanceScopesWithUserPermissions;
    private Optional<Boolean> dynamicClientRegistrationEnabled;

    public Optional<List<String>> getRedirectUris() {
        return redirectUris;
    }

    public void setRedirectUris(Optional<List<String>> redirectUris) {
        this.redirectUris = redirectUris;
    }

    public Optional<List<String>> getGrantTypes() {
        return grantTypes;
    }

    public void setGrantTypes(Optional<List<String>> grantTypes) {
        this.grantTypes = grantTypes;
    }

    public Optional<String> getClientName() {
        return clientName;
    }

    public void setClientName(Optional<String> clientName) {
        this.clientName = clientName;
    }

    public Optional<List<String>> getScope() {
        return scope;
    }

    public void setScope(Optional<List<String>> scope) {
        this.scope = scope;
    }

    public Optional<List<String>> getAutoApproveScopes() {
        return autoApproveScopes;
    }

    public void setAutoApproveScopes(Optional<List<String>> autoApproveScopes) {
        this.autoApproveScopes = autoApproveScopes;
    }

    public Optional<Integer> getAccessTokenValiditySeconds() {
        return accessTokenValiditySeconds;
    }

    public void setAccessTokenValiditySeconds(Optional<Integer> accessTokenValiditySeconds) {
        this.accessTokenValiditySeconds = accessTokenValiditySeconds;
    }

    public Optional<Integer> getRefreshTokenValiditySeconds() {
        return refreshTokenValiditySeconds;
    }

    public void setRefreshTokenValiditySeconds(Optional<Integer> refreshTokenValiditySeconds) {
        this.refreshTokenValiditySeconds = refreshTokenValiditySeconds;
    }

    public Optional<Integer> getIdTokenValiditySeconds() {
        return idTokenValiditySeconds;
    }

    public void setIdTokenValiditySeconds(Optional<Integer> idTokenValiditySeconds) {
        this.idTokenValiditySeconds = idTokenValiditySeconds;
    }

    public Optional<Map<String, Object>> getIdTokenCustomClaims() {
        return idTokenCustomClaims;
    }

    public void setIdTokenCustomClaims(Optional<Map<String, Object>> idTokenCustomClaims) {
        this.idTokenCustomClaims = idTokenCustomClaims;
    }

    public Optional<Boolean> getEnabled() {
        return enabled;
    }

    public void setEnabled(Optional<Boolean> enabled) {
        this.enabled = enabled;
    }

    public Optional<Set<String>> getIdentities() {
        return identities;
    }

    public void setIdentities(Optional<Set<String>> identities) {
        this.identities = identities;
    }

    public Optional<Set<String>> getOauth2Identities() {
        return oauth2Identities;
    }

    public void setOauth2Identities(Optional<Set<String>> oauth2Identities) {
        this.oauth2Identities = oauth2Identities;
    }

    public Optional<String> getCertificate() {
        return certificate;
    }

    public void setCertificate(Optional<String> certificate) {
        this.certificate = certificate;
    }

    public Optional<Boolean> getEnhanceScopesWithUserPermissions() {
        return enhanceScopesWithUserPermissions;
    }

    public void setEnhanceScopesWithUserPermissions(Optional<Boolean> enhanceScopesWithUserPermissions) {
        this.enhanceScopesWithUserPermissions = enhanceScopesWithUserPermissions;
    }

    public Optional<Boolean> isDynamicClientRegistrationEnabled() {
        return dynamicClientRegistrationEnabled;
    }

    public void setDynamicClientRegistrationEnabled(Optional<Boolean> dynamicClientRegistrationEnabled) {
        this.dynamicClientRegistrationEnabled = dynamicClientRegistrationEnabled;
    }

    public Client patch(Client toPatch) {

        SetterUtils.safeSet(toPatch::setRedirectUris, this.getRedirectUris());
        SetterUtils.safeSet(toPatch::setGrantTypes, this.getGrantTypes());
        SetterUtils.safeSet(toPatch::setClientName, this.getClientName());
        SetterUtils.safeSet(toPatch::setScope, this.getScope());
        SetterUtils.safeSet(toPatch::setAutoApproveScopes, this.getAutoApproveScopes());
        SetterUtils.safeSet(toPatch::setAccessTokenValiditySeconds, this.getAccessTokenValiditySeconds(), int.class);
        SetterUtils.safeSet(toPatch::setRefreshTokenValiditySeconds, this.getRefreshTokenValiditySeconds(), int.class);
        SetterUtils.safeSet(toPatch::setIdTokenValiditySeconds, this.getIdTokenValiditySeconds(), int.class);
        SetterUtils.safeSet(toPatch::setIdTokenCustomClaims, this.getIdTokenCustomClaims());
        SetterUtils.safeSet(toPatch::setEnabled, this.getEnabled(), boolean.class);
        SetterUtils.safeSet(toPatch::setIdentities, this.getIdentities());
        SetterUtils.safeSet(toPatch::setOauth2Identities, this.getOauth2Identities());
        SetterUtils.safeSet(toPatch::setCertificate, this.getCertificate());
        SetterUtils.safeSet(toPatch::setEnhanceScopesWithUserPermissions, this.getEnhanceScopesWithUserPermissions(), boolean.class);
        SetterUtils.safeSet(toPatch::setDynamicClientRegistrationEnabled, this.isDynamicClientRegistrationEnabled(), boolean.class);

        return toPatch;
    }
}
