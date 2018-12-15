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
package io.gravitee.am.gateway.handler.oidc.exception;

import io.gravitee.am.common.oauth2.exception.OAuth2Exception;
import io.gravitee.common.http.HttpStatusCode;

/**
 * Note that for security reasons, to inhibit brute force attacks, endpoints MUST NOT return the HTTP 404 Not Found status code.
 * https://openid.net/specs/openid-connect-registration-1_0.html#ReadError
 *
 * @author Alexandre FARIA (lusoalex at github.com)
 * @author GraviteeSource Team
 */
public class ClientRegistrationDisabledException extends OAuth2Exception {

    public ClientRegistrationDisabledException() {
        super("Not allowed to access to this resource.");
    }

    @Override
    public String getOAuth2ErrorCode() {
        return "registration_not_allowed";
    }

    @Override
    public int getHttpStatusCode() {
        return HttpStatusCode.FORBIDDEN_403;
    }
}
