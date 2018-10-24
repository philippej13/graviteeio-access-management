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

import io.gravitee.am.model.Client;

import java.util.List;

/**
 * @author Alexandre FARIA (lusoalex at github.com)
 * @author GraviteeSource Team
 */
public interface GrantTypeService {

    /**
     * Throw InvalidClientMetadataException if null or empty, or contains unknown grant types.
     * @param grantTypes Array of grant_type to validate.
     */
    boolean isValideGrantType(List<String> grantTypes);

    /**
     * Throw InvalidClientMetadataException if null or contains unknown grant type.
     * @param grantType String grant_type to validate.
     */
    boolean isValideGrantType(String grantType);

    /**
     * As specified in openid specs, ensure correspondence between response_type and grant_type.
     * Here is the following table lists response_type --> expected grant_type.
     * code                : authorization_code
     * id_token            : implicit
     * token id_token      : implicit
     * code id_token       : authorization_code, implicit
     * code token          : authorization_code, implicit
     * code token id_token : authorization_code, implicit
     *
     * @param client Client to analyse.
     * @return Client updated Client
     */
    Client completeGrantTypeCorrespondance(Client client);
}
