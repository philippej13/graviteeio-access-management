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
package io.gravitee.am.service.model.openid;

import io.gravitee.am.model.oidc.DynamicClientRegistrationSettings;
import io.gravitee.am.service.utils.SetterUtils;

import java.util.Optional;

/**
 * @author Alexandre FARIA (lusoalex at github.com)
 * @author GraviteeSource Team
 */
public class PatchDCRSettings {

    public PatchDCRSettings() {}

    /**
     * Allow localhost host as redirect_uri
     */
    private Optional<Boolean> allowLocalhostRedirectUri;

    /**
     * Allow unsecured http scheme into redirect_uri
     */
    private Optional<Boolean> allowHttpSchemeRedirectUri;

    /**
     * Allow wildcard redirect uri
     */
    private Optional<Boolean> allowWildCardRedirectUri;

    /**
     * Domain Dynamic Client Registration enabled
     */
    private Optional<Boolean> isEnabled;

    /**
     * Domain open Dynamic Client Registration enabled
     */
    private Optional<Boolean> isOpenRegistrationEnabled;


    public Optional<Boolean> getAllowLocalhostRedirectUri() {
        return allowLocalhostRedirectUri;
    }

    public void setAllowLocalhostRedirectUri(Optional<Boolean> allowLocalhostRedirectUri) {
        this.allowLocalhostRedirectUri = allowLocalhostRedirectUri;
    }

    public Optional<Boolean> getAllowHttpSchemeRedirectUri() {
        return allowHttpSchemeRedirectUri;
    }

    public void setAllowHttpSchemeRedirectUri(Optional<Boolean> allowHttpSchemeRedirectUri) {
        this.allowHttpSchemeRedirectUri = allowHttpSchemeRedirectUri;
    }

    public Optional<Boolean> getAllowWildCardRedirectUri() {
        return allowWildCardRedirectUri;
    }

    public void setAllowWildCardRedirectUri(Optional<Boolean> allowWildCardRedirectUri) {
        this.allowWildCardRedirectUri = allowWildCardRedirectUri;
    }

    public Optional<Boolean> isEnabled() {
        return isEnabled;
    }

    public void setEnabled(Optional<Boolean> enabled) {
        this.isEnabled = enabled;
    }

    public Optional<Boolean> isOpenRegistrationEnabled() {
        return isOpenRegistrationEnabled;
    }

    public void setOpenRegistrationEnabled(Optional<Boolean> openRegistrationEnabled) {
        this.isOpenRegistrationEnabled = openRegistrationEnabled;
    }


    public DynamicClientRegistrationSettings patch(DynamicClientRegistrationSettings toPatch) {
        DynamicClientRegistrationSettings result=toPatch!=null?toPatch:DynamicClientRegistrationSettings.defaultSettings();

        SetterUtils.safeSet(result::setAllowWildCardRedirectUri, this.getAllowWildCardRedirectUri(), boolean.class);
        SetterUtils.safeSet(result::setAllowHttpSchemeRedirectUri, this.getAllowHttpSchemeRedirectUri(), boolean.class);
        SetterUtils.safeSet(result::setAllowLocalhostRedirectUri, this.getAllowLocalhostRedirectUri(), boolean.class);
        SetterUtils.safeSet(result::setOpenRegistrationEnabled, this.isOpenRegistrationEnabled, boolean.class);
        SetterUtils.safeSet(result::setEnabled,this.isEnabled, boolean.class);

        return result;
    }
}
