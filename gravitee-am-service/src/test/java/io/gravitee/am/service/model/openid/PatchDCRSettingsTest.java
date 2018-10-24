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
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.Optional;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * @author Alexandre FARIA (lusoalex at github.com)
 * @author GraviteeSource Team
 */
@RunWith(JUnit4.class)
public class PatchDCRSettingsTest {

    @Test
    public void testPatchDefaultSettings() {
        PatchDCRSettings emptySettings = new PatchDCRSettings();
        DynamicClientRegistrationSettings result = emptySettings.patch(null);

        assertFalse("should be disabled by default", result.isEnabled());
        assertFalse("should be disabled by default", result.isOpenRegistrationEnabled());
        assertFalse("should be disabled by default", result.isAllowLocalhostRedirectUri());
        assertFalse("should be disabled by default", result.isAllowLocalhostRedirectUri());
        assertFalse("should be disabled by default", result.isAllowWildCardRedirectUri());
    }

    @Test
    public void testPatch() {
        PatchDCRSettings patcher = new PatchDCRSettings();
        patcher.setEnabled(Optional.of(false));
        patcher.setOpenRegistrationEnabled(Optional.empty());

        DynamicClientRegistrationSettings toPatch = DynamicClientRegistrationSettings.defaultSettings();
        toPatch.setEnabled(true);
        toPatch.setOpenRegistrationEnabled(true);
        toPatch.setAllowLocalhostRedirectUri(true);

        DynamicClientRegistrationSettings result = patcher.patch(toPatch);

        assertFalse("should be disabled by default", result.isEnabled());
        assertFalse("should be disabled by default", result.isOpenRegistrationEnabled());
        assertTrue("should be disabled by default", result.isAllowLocalhostRedirectUri());
    }
}
