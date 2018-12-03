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
import io.gravitee.am.gateway.handler.oauth2.exception.InvalidTokenException;
import io.gravitee.am.gateway.handler.users.RegisterService;
import io.gravitee.am.gateway.handler.vertx.utils.UriBuilderRequest;
import io.gravitee.am.model.User;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
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
public class ResetPasswordRequestParseHandler implements Handler<RoutingContext> {

    private static final Logger logger = LoggerFactory.getLogger(ResetPasswordRequestParseHandler.class);
    private static final String TOKEN_PARAM  = "token";
    private static final String ERROR_PARAM = "error";
    private static final String SUCCESS_PARAM = "success";

    private RegisterService registerService;

    public ResetPasswordRequestParseHandler(RegisterService registerService) {
        this.registerService = registerService;
    }

    @Override
    public void handle(RoutingContext context) {
        String token = context.request().getParam(TOKEN_PARAM);
        String error = context.request().getParam(ERROR_PARAM);
        String success = context.request().getParam(SUCCESS_PARAM);

        // reset password completed, continue
        if (success != null) {
            context.next();
            return;
        }

        // user has been redirected due to errors, continue
        if (error != null) {
            context.next();
            return;
        }

        // missing required token param
        // redirect user to reset password with error message
        if (token == null) {
            redirectToErrorResetPasswordPage(context, "token_missing");
            return;
        }

        parseToken(token, handler -> {
            if (handler.failed()) {
                redirectToErrorResetPasswordPage(context, "invalid_token");
                return;
            }

            context.put("user", handler.result());
            context.next();
        });
    }

    private void parseToken(String token, Handler<AsyncResult<User>> handler) {
        registerService.verifyToken(token)
                .subscribe(
                        user -> handler.handle(Future.succeededFuture(user)),
                        error -> handler.handle(Future.failedFuture(error)),
                        () -> handler.handle(Future.failedFuture(new InvalidTokenException("The JWT token is invalid"))));
    }

    private void redirectToErrorResetPasswordPage(RoutingContext context, String error) {
        try {
            String uri = UriBuilderRequest.resolveProxyRequest(context.request(), context.request().path(), Collections.singletonMap("error", error));
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
