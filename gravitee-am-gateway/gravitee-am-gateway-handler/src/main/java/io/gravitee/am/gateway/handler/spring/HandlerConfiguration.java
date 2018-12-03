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
package io.gravitee.am.gateway.handler.spring;

import io.gravitee.am.gateway.handler.auth.UserAuthenticationManager;
import io.gravitee.am.gateway.handler.auth.idp.IdentityProviderManager;
import io.gravitee.am.gateway.handler.auth.idp.impl.IdentityProviderManagerImpl;
import io.gravitee.am.gateway.handler.auth.impl.UserAuthenticationManagerImpl;
import io.gravitee.am.gateway.handler.email.EmailService;
import io.gravitee.am.gateway.handler.email.impl.EmailServiceImpl;
import io.gravitee.am.gateway.handler.jwt.JwtService;
import io.gravitee.am.gateway.handler.jwt.impl.JwtServiceImpl;
import io.gravitee.am.gateway.handler.oauth2.spring.OAuth2Configuration;
import io.gravitee.am.gateway.handler.oidc.spring.OpenIDConfiguration;
import io.gravitee.am.gateway.handler.page.PageManager;
import io.gravitee.am.gateway.handler.page.impl.PageManagerImpl;
import io.gravitee.am.gateway.handler.scim.spring.SCIMConfiguration;
import io.gravitee.am.gateway.handler.users.spring.UsersConfiguration;
import io.gravitee.am.gateway.handler.vertx.spring.SecurityDomainRouterConfiguration;
import io.gravitee.am.gateway.service.spring.ServiceConfiguration;
import io.gravitee.am.service.authentication.crypto.password.PasswordEncoder;
import io.gravitee.am.service.authentication.crypto.password.bcrypt.BCryptPasswordEncoder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

/**
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
@Configuration
@Import({
        ServiceConfiguration.class,
        OAuth2Configuration.class,
        OpenIDConfiguration.class,
        SCIMConfiguration.class,
        UsersConfiguration.class,
        SecurityDomainRouterConfiguration.class
})
public class HandlerConfiguration {

    @Bean
    public IdentityProviderManager identityProviderManager() {
        return new IdentityProviderManagerImpl();
    }

    @Bean
    public UserAuthenticationManager userAuthenticationManager() {
        return new UserAuthenticationManagerImpl();
    }

    @Bean
    public JwtService jwtService() {
        return new JwtServiceImpl();
    }

    @Bean
    public EmailService emailService() {
        return new EmailServiceImpl();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public PageManager pageManager() {
        return new PageManagerImpl();
    }
}
