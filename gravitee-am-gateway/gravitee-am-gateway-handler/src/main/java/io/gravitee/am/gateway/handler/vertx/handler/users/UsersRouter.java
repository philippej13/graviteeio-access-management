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
package io.gravitee.am.gateway.handler.vertx.handler.users;

import io.gravitee.am.gateway.handler.users.RegisterService;
import io.gravitee.am.gateway.handler.vertx.handler.users.endpoint.TokenParseHandler;
import io.gravitee.am.gateway.handler.vertx.handler.users.endpoint.password.*;
import io.gravitee.am.gateway.handler.vertx.handler.users.endpoint.register.RegisterConfirmationEndpointHandler;
import io.gravitee.am.gateway.handler.vertx.handler.users.endpoint.register.RegisterConfirmationRequestParseHandler;
import io.gravitee.am.gateway.handler.vertx.handler.users.endpoint.register.RegistrationConfirmationEndpointHandler;
import io.gravitee.am.gateway.handler.vertx.handler.users.endpoint.register.RegistrationConfirmationRequestParseHandler;
import io.vertx.core.Handler;
import io.vertx.core.http.HttpMethod;
import io.vertx.reactivex.core.Vertx;
import io.vertx.reactivex.ext.web.Router;
import io.vertx.reactivex.ext.web.RoutingContext;
import io.vertx.reactivex.ext.web.templ.ThymeleafTemplateEngine;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
public class UsersRouter {

    @Autowired
    private Vertx vertx;

    @Autowired
    private ThymeleafTemplateEngine thymeleafTemplateEngine;

    @Autowired
    private RegisterService registerService;

    public Router route() {
        // Create the Users router
        final Router router = Router.router(vertx);

        // Create the Users endpoints
        Handler<RoutingContext> tokenParseHandler = new TokenParseHandler(registerService);

        Handler<RoutingContext> registrationRequestParseHandler = new RegistrationConfirmationRequestParseHandler(registerService);
        Handler<RoutingContext> registrationHandler = new RegistrationConfirmationEndpointHandler(thymeleafTemplateEngine);
        Handler<RoutingContext> registerRequestParseHandler = new RegisterConfirmationRequestParseHandler();
        Handler<RoutingContext> registerHandler = new RegisterConfirmationEndpointHandler(registerService);

        Handler<RoutingContext> forgotPasswordHandler = new ForgotPasswordEndpointHandler(thymeleafTemplateEngine);
        Handler<RoutingContext> forgotPasswordSubmissionHandler = new ForgotPasswordSubmissionEndpointHandler(registerService);

        Handler<RoutingContext> resetPasswordRequestParseHandler = new ResetPasswordRequestParseHandler(registerService);
        Handler<RoutingContext> resetPasswordHandler = new ResetPasswordEndpointHandler(thymeleafTemplateEngine);
        Handler<RoutingContext> resetPasswordSubmissionRequestParseHandler = new ResetPasswordSubmissionRequestParseHandler();
        Handler<RoutingContext> resetPasswordSubmissionHandler = new ResetPasswordSubmissionEndpointHandler(registerService);

        // Declare Users routes
        router.route(HttpMethod.GET,"/confirmRegistration")
                .handler(registrationRequestParseHandler)
                .handler(registrationHandler);
        router.route(HttpMethod.POST, "/confirmRegistration")
                .handler(registerRequestParseHandler)
                .handler(tokenParseHandler)
                .handler(registerHandler);
        router.route(HttpMethod.GET,"/forgotPassword")
                .handler(forgotPasswordHandler);
        router.route(HttpMethod.POST, "/forgotPassword")
                .handler(forgotPasswordSubmissionHandler);
        router.route(HttpMethod.GET,"/resetPassword")
                .handler(resetPasswordRequestParseHandler)
                .handler(resetPasswordHandler);
        router.route(HttpMethod.POST, "/resetPassword")
                .handler(resetPasswordSubmissionRequestParseHandler)
                .handler(tokenParseHandler)
                .handler(resetPasswordSubmissionHandler);

        return router;
    }
}
