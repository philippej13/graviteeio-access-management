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
package io.gravitee.am.service;

import io.gravitee.am.service.impl.ResponseTypeServiceImpl;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.Arrays;

/**
 * @author Alexandre FARIA (lusoalex at github.com)
 * @author GraviteeSource Team
 */
@RunWith(JUnit4.class)
public class ResponseTypeServiceTest {

    private ResponseTypeService responseTypeService = new ResponseTypeServiceImpl();

    @Test
    public void test_code_token_id_token() {
        boolean isValid = this.responseTypeService.isValideResponseType(Arrays.asList("code", "token", "id_token"));
        Assert.assertTrue("Were expecting to be true",isValid);
    }

    @Test
    public void test_unknown_response_type() {
        boolean isValid = this.responseTypeService.isValideResponseType(Arrays.asList("unknown"));
        Assert.assertFalse("Were expecting to be false",isValid);
    }

    @Test
    public void test_empty_response_type() {
        boolean isValid = this.responseTypeService.isValideResponseType(Arrays.asList());
        Assert.assertFalse("Were expecting to be false",isValid);
    }
}
