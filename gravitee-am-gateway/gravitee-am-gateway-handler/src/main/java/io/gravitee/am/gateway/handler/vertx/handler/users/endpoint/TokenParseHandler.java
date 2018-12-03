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
package io.gravitee.am.gateway.handler.vertx.handler.users.endpoint;

import io.gravitee.am.gateway.handler.oauth2.exception.InvalidTokenException;
import io.gravitee.am.gateway.handler.users.RegisterService;
import io.gravitee.am.model.User;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.reactivex.ext.web.RoutingContext;

/**
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
public class TokenParseHandler implements Handler<RoutingContext> {

    private static final String tokenParam = "token";
    private RegisterService registerService;

    public TokenParseHandler(RegisterService registerService) {
        this.registerService = registerService;
    }

    @Override
    public void handle(RoutingContext context) {
        final String token = context.request().getParam(tokenParam);

        parseToken(token, handler -> {
            if (handler.failed()) {
                context.fail(401);
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
}
