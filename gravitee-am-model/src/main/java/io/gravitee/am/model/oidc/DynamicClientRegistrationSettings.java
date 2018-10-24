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
package io.gravitee.am.model.oidc;

/**
 * @author Alexandre FARIA (lusoalex at github.com)
 * @author GraviteeSource Team
 */
public class DynamicClientRegistrationSettings {

    /**
     * Allow localhost host as redirect_uri
     */
    private boolean allowLocalhostRedirectUri;

    /**
     * Allow unsecured http scheme into redirect_uri
     */
    private boolean allowHttpSchemeRedirectUri;

    /**
     * Allow wildcard redirect uri
     */
    private boolean allowWildCardRedirectUri;

    /**
     * Domain Dynamic Client Registration enabled
     */
    private boolean isEnabled;

    /**
     * Domain open Dynamic Client Registration enabled
     */
    private boolean isOpenRegistrationEnabled;


    public boolean isAllowLocalhostRedirectUri() {
        return allowLocalhostRedirectUri;
    }

    public void setAllowLocalhostRedirectUri(boolean allowLocalhostRedirectUri) {
        this.allowLocalhostRedirectUri = allowLocalhostRedirectUri;
    }

    public boolean isAllowHttpSchemeRedirectUri() {
        return allowHttpSchemeRedirectUri;
    }

    public void setAllowHttpSchemeRedirectUri(boolean allowHttpSchemeRedirectUri) {
        this.allowHttpSchemeRedirectUri = allowHttpSchemeRedirectUri;
    }

    public boolean isEnabled() {
        return isEnabled;
    }

    public void setEnabled(boolean enabled) {
        this.isEnabled = enabled;
    }

    public boolean isOpenRegistrationEnabled() {
        return isOpenRegistrationEnabled;
    }

    public void setOpenRegistrationEnabled(boolean openRegistrationEnabled) {
        this.isOpenRegistrationEnabled = openRegistrationEnabled;
    }

    public boolean isAllowWildCardRedirectUri() {
        return allowWildCardRedirectUri;
    }

    public void setAllowWildCardRedirectUri(boolean allowWildCardRedirectUri) {
        this.allowWildCardRedirectUri = allowWildCardRedirectUri;
    }

    public static DynamicClientRegistrationSettings defaultSettings() {
        //By default all boolean are set to false.
        return new DynamicClientRegistrationSettings();
    }
}
