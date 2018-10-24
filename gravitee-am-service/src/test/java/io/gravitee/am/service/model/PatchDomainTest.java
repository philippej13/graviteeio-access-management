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

import io.gravitee.am.model.Domain;
import io.gravitee.am.model.oidc.DynamicClientRegistrationSettings;
import io.gravitee.am.model.oidc.OIDCSettings;
import io.gravitee.am.service.model.openid.PatchDCRSettings;
import io.gravitee.am.service.model.openid.PatchOIDCSettings;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

/**
 * @author Alexandre FARIA (lusoalex at github.com)
 * @author GraviteeSource Team
 */
@RunWith(JUnit4.class)
public class PatchDomainTest {

    @Test
    public void testPatchWithoutOidc() {
        //Build patcher
        PatchDomain patch = new PatchDomain();
        patch.setDescription(Optional.of("expectedDescription"));
        patch.setName(Optional.empty());

        //Build object to patch
        Domain toPatch = new Domain();
        toPatch.setDescription("oldDescription");
        toPatch.setName("oldName");
        toPatch.setPath("expectedPath");

        //apply patch
        Domain result = patch.patch(toPatch);

        //check.
        assertNotNull("was expecting a domain",result);
        assertEquals("description should have been updated","expectedDescription", result.getDescription());
        assertNull("name should have been set to null",result.getName());
        assertEquals("path should not be updated","expectedPath", result.getPath());
    }

    @Test
    public void testPatchWithEmptyOidc() {
        //Build patcher
        PatchDomain patch = new PatchDomain();
        patch.setOidc(Optional.empty());

        //Build object to patch with DCR enabled
        DynamicClientRegistrationSettings dcr = DynamicClientRegistrationSettings.defaultSettings();
        OIDCSettings oidc = OIDCSettings.defaultSettings();
        Domain toPatch = new Domain();

        dcr.setEnabled(true);
        oidc.setDynamicClientRegistration(dcr);
        toPatch.setOidc(oidc);

        //apply patch
        Domain result = patch.patch(toPatch);

        //check.
        assertNotNull("was expecting a domain",result);
        assertNotNull(result.getOidc());
        assertNotNull(result.getOidc().getDynamicClientRegistration());
        assertFalse("should have been disabled",result.getOidc().getDynamicClientRegistration().isEnabled());
    }

    @Test
    public void testPatchWithEnabledOidc() {
        //Build patcher
        PatchDCRSettings dcrPatcher = new PatchDCRSettings();
        dcrPatcher.setEnabled(Optional.of(true));
        PatchOIDCSettings oidcPatcher = new PatchOIDCSettings();
        oidcPatcher.setDynamicClientRegistration(Optional.of(dcrPatcher));
        PatchDomain patch = new PatchDomain();
        patch.setOidc(Optional.of(oidcPatcher));

        //Build object to patch with DCR enabled
        Domain toPatch = new Domain();
        toPatch.setOidc(OIDCSettings.defaultSettings());

        //apply patch
        Domain result = patch.patch(toPatch);

        //check.
        assertNotNull("was expecting a domain",result);
        assertNotNull(result.getOidc());
        assertNotNull(result.getOidc().getDynamicClientRegistration());
        assertTrue("should have been enabled",result.getOidc().getDynamicClientRegistration().isEnabled());
    }
}
