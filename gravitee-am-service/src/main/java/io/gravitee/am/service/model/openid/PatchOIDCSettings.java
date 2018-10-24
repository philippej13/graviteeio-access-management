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

import com.fasterxml.jackson.annotation.JsonProperty;
import io.gravitee.am.model.oidc.DynamicClientRegistrationSettings;
import io.gravitee.am.model.oidc.OIDCSettings;
import java.util.Optional;

/**
 * @author Alexandre FARIA (lusoalex at github.com)
 * @author GraviteeSource Team
 */
public class PatchOIDCSettings {

    public PatchOIDCSettings() {}

    @JsonProperty("dynamicClientRegistration")
    private Optional<PatchDCRSettings> dynamicClientRegistration;

    public Optional<PatchDCRSettings> getDynamicClientRegistration() {
        return dynamicClientRegistration;
    }

    public void setDynamicClientRegistration(Optional<PatchDCRSettings> dynamicClientRegistration) {
        this.dynamicClientRegistration = dynamicClientRegistration;
    }

    public OIDCSettings patch(OIDCSettings toPatch) {

        //If source may be null, in such case init with default values
        OIDCSettings result=toPatch!=null?toPatch:OIDCSettings.defaultSettings();

        if(getDynamicClientRegistration()!=null) {
            //If present apply settings, else return default settings.
            if(getDynamicClientRegistration().isPresent()) {
                PatchDCRSettings patcher = getDynamicClientRegistration().get();
                DynamicClientRegistrationSettings source = result.getDynamicClientRegistration();
                result.setDynamicClientRegistration(patcher.patch(source));
            } else {
                result.setDynamicClientRegistration(DynamicClientRegistrationSettings.defaultSettings());
            }
        }

        return result;
    }
}
