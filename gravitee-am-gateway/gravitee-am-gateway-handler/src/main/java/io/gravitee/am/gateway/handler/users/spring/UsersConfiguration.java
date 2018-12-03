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
package io.gravitee.am.gateway.handler.users.spring;

import io.gravitee.am.gateway.handler.jwt.JwtBuilder;
import io.gravitee.am.gateway.handler.jwt.JwtParser;
import io.gravitee.am.gateway.handler.jwt.impl.JJwtBuilder;
import io.gravitee.am.gateway.handler.jwt.impl.JJwtParser;
import io.gravitee.am.gateway.handler.users.RegisterService;
import io.gravitee.am.gateway.handler.users.impl.RegisterServiceImpl;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.Key;

/**
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
@Configuration
public class UsersConfiguration {

    @Value("${jwt.kid:default-gravitee-am-kid}")
    private String kid;

    @Value("${jwt.secret:s3cR3t4grAv1t3310AMS1g1ingDftK3y}")
    private String signingKeySecret;

    @Bean
    public RegisterService registerService() {
        return new RegisterServiceImpl();
    }

    @Bean
    public JwtParser jwtParser() {
        // jwt parser for token user registration
        JwtParser jwtParser = new JJwtParser(Jwts.parser().setSigningKey(key()));
        return jwtParser;
    }

    @Bean
    public JwtBuilder jwtBuilder() {
        // jwt builder for reset password
        JwtBuilder jwtBuilder = new JJwtBuilder(Jwts.builder().signWith(key()).setHeaderParam(JwsHeader.KEY_ID, kid));
        return jwtBuilder;
    }

    @Bean
    public Key key() {
        // HMAC key to sign/verify JWT used for email purpose
        Key key = Keys.hmacShaKeyFor(signingKeySecret.getBytes());
        return key;
    }
}
