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
import io.gravitee.am.gateway.handler.vertx.utils.UriBuilderRequest;
import io.gravitee.am.service.exception.UserNotFoundException;
import io.vertx.core.Handler;
import io.vertx.core.http.HttpMethod;
import io.vertx.reactivex.core.MultiMap;
import io.vertx.reactivex.core.http.HttpServerRequest;
import io.vertx.reactivex.core.http.HttpServerResponse;
import io.vertx.reactivex.ext.web.RoutingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;

/**
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
public class ForgotPasswordSubmissionEndpointHandler implements Handler<RoutingContext> {

    private static final Logger logger = LoggerFactory.getLogger(ForgotPasswordSubmissionEndpointHandler.class);
    private static final String emailParam = "email";
    private static final String ERROR_PARAM = "error";
    private static final String SUCCESS_PARAM = "success";
    private static final String WARNING_PARAM = "warning";
    private RegisterService registerService;

    public ForgotPasswordSubmissionEndpointHandler(RegisterService registerService) {
        this.registerService = registerService;
    }

    @Override
    public void handle(RoutingContext context) {
        HttpServerRequest req = context.request();
        if (req.method() != HttpMethod.POST) {
            context.fail(405); // Must be a POST
        } else {
            if (!req.isExpectMultipart()) {
                throw new IllegalStateException("Form body not parsed - do you forget to include a BodyHandler?");
            }
            MultiMap params = req.formAttributes();
            String email = params.get(emailParam);
            if (email == null) {
                logger.warn("No email provided in form - did you forget to include a BodyHandler?");
                context.fail(400);
            } else {
                registerService.forgotPassword(email)
                        .subscribe(
                                () -> redirectToForgotPasswordPage(context, SUCCESS_PARAM, "forgot_password_completed"),
                                error -> {
                                    if (error instanceof UserNotFoundException) {
                                        redirectToForgotPasswordPage(context, WARNING_PARAM, "user_not_found");
                                    } else {
                                        redirectToForgotPasswordPage(context, ERROR_PARAM, error.getMessage());
                                    }
                                });
            }
        }
    }

    private void redirectToForgotPasswordPage(RoutingContext context, String paramName, String paramValue) {
        try {
            String uri = UriBuilderRequest.resolveProxyRequest(context.request(), context.request().path(), Collections.singletonMap(paramName, paramValue));
            doRedirect(context.response(), uri);
        } catch (Exception ex) {
            logger.error("An error occurs while redirecting to the forgot page", ex);
            context.fail(503);
        }
    }

    private void doRedirect(HttpServerResponse response, String url) {
        response.putHeader(HttpHeaders.LOCATION, url).setStatusCode(302).end();
    }
}
