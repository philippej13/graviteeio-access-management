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
package io.gravitee.am.management.service.impl;

import io.gravitee.am.common.email.Email;
import io.gravitee.am.common.email.EmailBuilder;
import io.gravitee.am.common.jwt.Claims;
import io.gravitee.am.common.oidc.StandardClaims;
import io.gravitee.am.identityprovider.api.DefaultUser;
import io.gravitee.am.management.core.event.EmailEvent;
import io.gravitee.am.management.service.IdentityProviderManager;
import io.gravitee.am.management.service.UserService;
import io.gravitee.am.management.service.exception.UserProviderNotFoundException;
import io.gravitee.am.model.User;
import io.gravitee.am.model.common.Page;
import io.gravitee.am.repository.management.api.UserRepository;
import io.gravitee.am.service.exception.UserNotFoundException;
import io.gravitee.am.service.exception.account.InvalidAccountException;
import io.gravitee.am.service.model.NewUser;
import io.gravitee.am.service.model.UpdateUser;
import io.gravitee.common.event.EventManager;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.reactivex.Completable;
import io.reactivex.Maybe;
import io.reactivex.Single;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.*;

/**
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
@Component("ManagementUserService")
public class UserServiceImpl implements UserService, InitializingBean {

    private static final String DEFAULT_IDP_PREFIX = "default-idp-";

    private Key key;

    @Value("${jwt.secret:s3cR3t4grAv1t3310AMS1g1ingDftK3y}")
    private String signingKeySecret;

    @Value("${jwt.issuer:https://gravitee.am}")
    private String issuer;

    @Value("${jwt.kid:default-gravitee-am-kid}")
    private String kid;

    @Value("${jwt.expire-after:604800}")
    private Integer expireAfter;

    @Value("${gateway.url:http://localhost:8092}")
    private String gatewayUrl;

    @Autowired
    private io.gravitee.am.service.UserService userService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private IdentityProviderManager identityProviderManager;

    @Autowired
    private EventManager eventManager;

    @Override
    public Single<Set<User>> findByDomain(String domain) {
        return userService.findByDomain(domain);
    }

    @Override
    public Single<Page<User>> findByDomain(String domain, int page, int size) {
        return userService.findByDomain(domain, page, size);
    }

    @Override
    public Maybe<User> findById(String id) {
        return userService.findById(id);
    }

    @Override
    public Single<User> create(String domain, NewUser newUser) {
        return Single.just(newUser.isPreRegistration())
                .flatMap(isPreRegistration -> {
                    // set source (currently default idp)
                    newUser.setSource(DEFAULT_IDP_PREFIX + domain);
                    newUser.setInternal(true);
                    if (isPreRegistration) {
                        // in pre registration mode an email will be sent to the user to complete his account
                        // and user will only be stored as 'readonly' account
                        newUser.setPassword(null);
                        newUser.setRegistrationCompleted(false);
                        newUser.setEnabled(false);
                        return userService.create(domain, newUser)
                                .doOnSuccess(user -> new Thread(() -> completeUserRegistration(user)).start());
                    } else {
                        newUser.setRegistrationCompleted(true);
                        newUser.setEnabled(true);
                        newUser.setDomain(domain);
                        // store user in its identity provider (currently only AM IDP is enabled, in the future we might want to store user in any external identity provider)
                        return identityProviderManager.getUserProvider(newUser.getSource())
                                .switchIfEmpty(Maybe.error(new UserProviderNotFoundException(DEFAULT_IDP_PREFIX + domain)))
                                .flatMapSingle(userProvider -> userProvider.create(convert(newUser)))
                                .flatMap(user -> {
                                    // AM 'users' collection is not made for authentication (but only management stuff)
                                    // clear password
                                    newUser.setPassword(null);
                                    return userService.create(domain, newUser);
                                });
                    }
                });
    }

    @Override
    public Single<User> update(String domain, String id, UpdateUser updateUser) {
        return userService.findById(id)
                .switchIfEmpty(Maybe.error(new UserNotFoundException(id)))
                .flatMapSingle(user -> identityProviderManager.getUserProvider(user.getSource())
                        .switchIfEmpty(Maybe.error(new UserProviderNotFoundException(user.getSource())))
                        .flatMapSingle(userProvider ->  userProvider.findByUsername(user.getUsername())
                                .map(idpUser -> Optional.of(idpUser))
                                .defaultIfEmpty(Optional.empty())
                                .flatMapSingle(optionalUser -> {
                                    if (!optionalUser.isPresent()) {
                                        return userService.update(domain, id, updateUser);
                                    } else {
                                        return userProvider.update(convert(optionalUser.get(), updateUser))
                                                .flatMap(idpUser -> userService.update(domain, id, updateUser));
                                    }
                                })));
    }

    @Override
    public Completable delete(String userId) {
        return userService.findById(userId)
                .switchIfEmpty(Maybe.error(new UserNotFoundException(userId)))
                .flatMapCompletable(user -> identityProviderManager.getUserProvider(user.getSource())
                        .switchIfEmpty(Maybe.error(new UserProviderNotFoundException(user.getSource())))
                        .flatMapCompletable(userProvider -> userProvider.findByUsername(user.getUsername())
                                .map(idpUser -> Optional.of(idpUser))
                                .defaultIfEmpty(Optional.empty())
                                .flatMapCompletable(optionalUser -> {
                                    if (!optionalUser.isPresent()) {
                                        // idp user does not exist, only remove AM user
                                        return userRepository.delete(userId);
                                    } else {
                                        return userProvider.delete(optionalUser.get().getId())
                                                .andThen(userService.delete(userId));
                                    }
                                })));
    }

    @Override
    public Completable resetPassword(String domain, String userId, String password) {
        return userService.findById(userId)
                .switchIfEmpty(Maybe.error(new UserNotFoundException(userId)))
                .flatMapSingle(user -> identityProviderManager.getUserProvider(user.getSource())
                        .switchIfEmpty(Maybe.error(new UserProviderNotFoundException(user.getSource())))
                        .flatMapSingle(userProvider ->  userProvider.findByUsername(user.getUsername())
                                .map(idpUser -> Optional.of(idpUser))
                                .defaultIfEmpty(Optional.empty())
                                .flatMapSingle(optionalUser -> {
                                    if (!optionalUser.isPresent()) {
                                        return userProvider.create(convert(user));
                                    } else {
                                        io.gravitee.am.identityprovider.api.User idpUser = optionalUser.get();
                                        ((DefaultUser)idpUser).setCredentials(password);
                                        return userProvider.update(idpUser);
                                    }
                                }))
                        .flatMap(idpUser -> {
                            if (user.isPreRegistration()) {
                                user.setRegistrationCompleted(true);
                            }
                            return userRepository.update(user);
                        })).toCompletable();
    }

    @Override
    public Completable sendRegistrationConfirmation(String userId) {
        return findById(userId)
                .switchIfEmpty(Maybe.error(new UserNotFoundException(userId)))
                .map(user -> {
                    if (!user.isPreRegistration()) {
                        throw new InvalidAccountException("Pre-registration is disabled for the user " + userId);
                    }
                    if (user.isPreRegistration() && user.isRegistrationCompleted()) {
                        throw new InvalidAccountException("Registration is completed for the user " + userId);
                    }
                    return user;
                })
                .doOnSuccess(user -> new Thread(() -> completeUserRegistration(user)).start())
                .toSingle()
                .toCompletable();
    }

    @Override
    public void afterPropertiesSet() {
        // init JWT signing key
        key = Keys.hmacShaKeyFor(signingKeySecret.getBytes());
    }

    private void completeUserRegistration(User user) {
        Map<String, Object> params = prepareUserRegistration(user);

        Email email = new EmailBuilder()
                .to(user.getEmail())
                .subject("User registration - " + user.getFirstName() + " " + user.getLastName())
                .template(EmailBuilder.EmailTemplate.USER_REGISTRATION)
                .params(params)
                .build();

        eventManager.publishEvent(EmailEvent.SEND, email);
    }

    private Map<String, Object> prepareUserRegistration(User user) {
        // generate a JWT to store user's information and for security purpose
        final Map<String, Object> claims = new HashMap<>();
        claims.put(Claims.iss, issuer);
        claims.put(Claims.sub, user.getId());
        claims.put(StandardClaims.EMAIL, user.getEmail());
        claims.put(StandardClaims.GIVEN_NAME, user.getFirstName());
        claims.put(StandardClaims.FAMILY_NAME, user.getLastName());

        final String token = Jwts.builder()
                .signWith(key)
                .setHeaderParam(JwsHeader.KEY_ID, kid)
                .setClaims(claims)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expireAfter))
                .compact();

        String entryPoint = gatewayUrl;
        if (entryPoint != null && entryPoint.endsWith("/")) {
            entryPoint = entryPoint.substring(0, entryPoint.length() - 1);
        }

        String registrationUrl = entryPoint + "/" + user.getDomain() + "/users/confirmRegistration?token=" + token;

        Map<String, Object> params = new HashMap<>();
        params.put("user", user);
        params.put("registrationUrl", registrationUrl);
        params.put("token", token);

        return params;
    }

    private io.gravitee.am.identityprovider.api.User convert(NewUser newUser) {
        DefaultUser user = new DefaultUser(newUser.getUsername());
        user.setCredentials(newUser.getPassword());

        Map<String, Object> additionalInformation = new HashMap<>();
        if (newUser.getFirstName() != null) {
            additionalInformation.put(StandardClaims.GIVEN_NAME, newUser.getFirstName());
        }
        if (newUser.getLastName() != null) {
            additionalInformation.put(StandardClaims.FAMILY_NAME, newUser.getLastName());
        }
        if (newUser.getEmail() != null) {
            additionalInformation.put(StandardClaims.EMAIL, newUser.getEmail());
        }
        if (newUser.getAdditionalInformation() != null) {
            additionalInformation.putAll(newUser.getAdditionalInformation());
        }
        user.setAdditionalInformation(additionalInformation);
        return user;
    }

    private io.gravitee.am.identityprovider.api.User convert(io.gravitee.am.identityprovider.api.User idpUser, UpdateUser updateUser) {
        // update additional information
        Map<String, Object> additionalInformation = idpUser.getAdditionalInformation() == null ? new HashMap<>() : new HashMap<>(idpUser.getAdditionalInformation());
        if (updateUser.getFirstName() != null) {
            additionalInformation.put(StandardClaims.GIVEN_NAME, updateUser.getFirstName());
        }
        if (updateUser.getLastName() != null) {
            additionalInformation.put(StandardClaims.FAMILY_NAME, updateUser.getLastName());
        }
        if (updateUser.getEmail() != null) {
            additionalInformation.put(StandardClaims.EMAIL, updateUser.getEmail());
        }
        if (updateUser.getAdditionalInformation() != null) {
            additionalInformation.putAll(updateUser.getAdditionalInformation());
        }
        ((DefaultUser) idpUser).setAdditionalInformation(additionalInformation);
        return idpUser;
    }

    private io.gravitee.am.identityprovider.api.User convert(User user) {
        DefaultUser idpUser = new DefaultUser(user.getUsername());
        idpUser.setCredentials(user.getPassword());

        Map<String, Object> additionalInformation = new HashMap<>();
        if (user.getFirstName() != null) {
            additionalInformation.put(StandardClaims.GIVEN_NAME, user.getFirstName());
        }
        if (user.getLastName() != null) {
            additionalInformation.put(StandardClaims.FAMILY_NAME, user.getLastName());
        }
        if (user.getEmail() != null) {
            additionalInformation.put(StandardClaims.EMAIL, user.getEmail());
        }
        if (user.getAdditionalInformation() != null) {
            additionalInformation.putAll(user.getAdditionalInformation());
        }
        idpUser.setAdditionalInformation(additionalInformation);
        return idpUser;
    }
}
