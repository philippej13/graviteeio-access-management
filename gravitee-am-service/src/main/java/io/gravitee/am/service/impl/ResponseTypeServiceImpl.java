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
package io.gravitee.am.service.impl;

import io.gravitee.am.model.Client;
import io.gravitee.am.service.ResponseTypeService;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static io.gravitee.am.common.oauth2.GrantType.AUTHORIZATION_CODE;
import static io.gravitee.am.common.oauth2.GrantType.IMPLICIT;
import static io.gravitee.am.common.oauth2.ResponseType.*;
import static io.gravitee.am.common.oidc.ResponseType.ID_TOKEN;

/**
 * @author Alexandre FARIA (lusoalex at github.com)
 * @author GraviteeSource Team
 */
@Component
public class ResponseTypeServiceImpl implements ResponseTypeService {

    private static final Set<String> VALID_RESPONSE_TYPES = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            CODE, TOKEN, ID_TOKEN
    )));

    /**
     * Throw InvalidClientMetadataException if null or empty, or contains unknown response types.
     * @param responseTypes Array of response_type to validate.
     */
    @Override
    public boolean isValideResponseType(List<String> responseTypes) {
        if (responseTypes == null || responseTypes.isEmpty()) {
            return false;
        }

        for (String responseType : responseTypes) {
            if (!this.isValideResponseType(responseType)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Throw InvalidClientMetadataException if null or contains unknown response types.
     * @param responseType String to response_type validate.
     */
    @Override
    public boolean isValideResponseType(String responseType) {
        return VALID_RESPONSE_TYPES.contains(responseType);
    }

    /**
     * Currently in the UI there's no response type settings on the client.
     * So we will add default response type according to selected grant_type.
     * authorization_code  : add code
     * implicit            : add token
     *
     * @param client Client to analyse.
     * @return Client updated Client
     */
    @Override
    public Client applyDefaultResponseType(Client client) {
        Set responseType = new HashSet<>();
        Set grantType = new HashSet<>(client.getAuthorizedGrantTypes());

        //If grant_type contains authorization_code, response_type must contains code
        if (grantType.contains(AUTHORIZATION_CODE)) {
            responseType.add(CODE);
        }

        //If grant_type contains implicit, response_type must contains token or id_token
        if (grantType.contains(IMPLICIT)) {
            responseType.add(TOKEN);
        }

        client.setResponseTypes((List<String>) responseType.stream().collect(Collectors.toList()));

        return client;
    }
}
