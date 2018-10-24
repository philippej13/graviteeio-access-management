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
import io.gravitee.am.model.oidc.OIDCSettings;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.Optional;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertNotNull;

/**
 * @author Alexandre FARIA (lusoalex at github.com)
 * @author GraviteeSource Team
 */
@RunWith(JUnit4.class)
public class PatchOIDCSettingsTest {

    @Test
    public void testPatchToNullValue() {
        //Build patcher
        PatchOIDCSettings nullSettings = new PatchOIDCSettings();

        //apply patch on null object
        OIDCSettings result = nullSettings.patch(null);

        assertNotNull(result);
        assertNotNull(result.getDynamicClientRegistration());
        assertFalse("should be disabled by default", result.getDynamicClientRegistration().isEnabled());
    }


    @Test
    public void testPatchToEmptyValue() {
        //Build patcher
        PatchOIDCSettings emptySettings = new PatchOIDCSettings();
        emptySettings.setDynamicClientRegistration(Optional.empty());

        //apply patch to empty object
        OIDCSettings result = emptySettings.patch(new OIDCSettings());

        assertNotNull(result);
        assertNotNull(result.getDynamicClientRegistration());
        assertFalse("should be disabled by default", result.getDynamicClientRegistration().isEnabled());
    }

    @Test
    public void testPatchSettingsToEmptyValue() {
        //Build patcher
        PatchOIDCSettings patcher = new PatchOIDCSettings();
        PatchDCRSettings dcrPatcher = new PatchDCRSettings();
        dcrPatcher.setEnabled(Optional.of(true));
        dcrPatcher.setAllowLocalhostRedirectUri(Optional.of(true));
        patcher.setDynamicClientRegistration(Optional.of(dcrPatcher));

        //apply patch
        OIDCSettings result = patcher.patch(new OIDCSettings());

        assertNotNull(result);
        assertNotNull(result.getDynamicClientRegistration());
        assertTrue("should be enabled",result.getDynamicClientRegistration().isEnabled());
        assertTrue("should be enabled",result.getDynamicClientRegistration().isAllowLocalhostRedirectUri());
        assertFalse("should be disabled by default", result.getDynamicClientRegistration().isOpenRegistrationEnabled());
    }

    @Test
    public void testPatchEmtpySettings() {
        //Build object to patch
        DynamicClientRegistrationSettings dcrSettings = new DynamicClientRegistrationSettings();
        dcrSettings.setEnabled(true);
        dcrSettings.setOpenRegistrationEnabled(false);
        dcrSettings.setAllowLocalhostRedirectUri(true);
        dcrSettings.setAllowHttpSchemeRedirectUri(false);
        dcrSettings.setAllowWildCardRedirectUri(true);
        OIDCSettings toPatch = new OIDCSettings();
        toPatch.setDynamicClientRegistration(dcrSettings);

        //Build patcher
        PatchOIDCSettings patcher = new PatchOIDCSettings();
        PatchDCRSettings dcrPatcher = new PatchDCRSettings();
        dcrPatcher.setEnabled(Optional.of(false));
        dcrPatcher.setOpenRegistrationEnabled(Optional.of(true));
        dcrPatcher.setAllowLocalhostRedirectUri(Optional.of(false));
        dcrPatcher.setAllowHttpSchemeRedirectUri(Optional.of(true));
        dcrPatcher.setAllowWildCardRedirectUri(Optional.of(false));
        patcher.setDynamicClientRegistration(Optional.of(dcrPatcher));

        //apply patch
        OIDCSettings result = patcher.patch(toPatch);

        assertNotNull(result);
        assertNotNull(result.getDynamicClientRegistration());
        assertFalse(result.getDynamicClientRegistration().isEnabled());
        assertTrue(result.getDynamicClientRegistration().isOpenRegistrationEnabled());
        assertFalse(result.getDynamicClientRegistration().isAllowLocalhostRedirectUri());
        assertTrue(result.getDynamicClientRegistration().isAllowHttpSchemeRedirectUri());
        assertFalse(result.getDynamicClientRegistration().isAllowWildCardRedirectUri());
    }
}
