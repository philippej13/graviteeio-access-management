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
package io.gravitee.am.gateway.handler.vertx.handler.users.endpoint.password;

import com.google.common.net.HttpHeaders;
import io.gravitee.am.gateway.handler.users.RegisterService;
import io.gravitee.am.gateway.handler.vertx.handler.users.endpoint.register.RegisterConfirmationEndpointHandler;
import io.gravitee.am.gateway.handler.vertx.utils.UriBuilderRequest;
import io.gravitee.am.model.User;
import io.vertx.core.Handler;
import io.vertx.reactivex.core.http.HttpServerResponse;
import io.vertx.reactivex.ext.web.RoutingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;

/**
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
public class ResetPasswordSubmissionEndpointHandler implements Handler<RoutingContext> {

    private static final Logger logger = LoggerFactory.getLogger(RegisterConfirmationEndpointHandler.class);
    private static final String passwordParam = "password";
    private RegisterService registerService;

    public ResetPasswordSubmissionEndpointHandler(RegisterService registerService) {
        this.registerService = registerService;
    }

    @Override
    public void handle(RoutingContext context) {
        final String password = context.request().getParam(passwordParam);
        User user = context.get("user");
        user.setPassword(password);

        registerService.resetPassword(user)
                .subscribe(
                        () -> redirectToResetPasswordPage(context, "success", "reset_password_completed"),
                        error -> redirectToResetPasswordPage(context, "error", "reset_password_failed"));
    }

    private void redirectToResetPasswordPage(RoutingContext context, String paramName, String paramValue) {
        try {
            String uri = UriBuilderRequest.resolveProxyRequest(context.request(), context.request().path(), Collections.singletonMap(paramName, paramValue));
            doRedirect(context.response(), uri);
        } catch (Exception ex) {
            logger.error("An error occurs while redirecting to the reset password page", ex);
            context.fail(503);
        }
    }

    private void doRedirect(HttpServerResponse response, String url) {
        response.putHeader(HttpHeaders.LOCATION, url).setStatusCode(302).end();
    }
}
