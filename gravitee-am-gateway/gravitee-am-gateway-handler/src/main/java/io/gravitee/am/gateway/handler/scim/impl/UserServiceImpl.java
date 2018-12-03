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
package io.gravitee.am.gateway.handler.scim.impl;

import io.gravitee.am.common.oidc.StandardClaims;
import io.gravitee.am.common.scim.UserClaims;
import io.gravitee.am.gateway.handler.scim.GroupService;
import io.gravitee.am.gateway.handler.scim.UserService;
import io.gravitee.am.gateway.handler.scim.exception.SCIMException;
import io.gravitee.am.gateway.handler.scim.exception.UniquenessException;
import io.gravitee.am.gateway.handler.scim.model.*;
import io.gravitee.am.model.Domain;
import io.gravitee.am.repository.management.api.UserRepository;
import io.gravitee.am.service.exception.AbstractManagementException;
import io.gravitee.am.service.exception.TechnicalManagementException;
import io.gravitee.am.service.exception.UserNotFoundException;
import io.gravitee.common.utils.UUID;
import io.reactivex.Completable;
import io.reactivex.Maybe;
import io.reactivex.Single;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.*;
import java.util.stream.Collectors;

/**
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
public class UserServiceImpl implements UserService {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserServiceImpl.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private GroupService groupService;

    @Autowired
    private Domain domain;

    @Override
    public Single<ListResponse<User>> list(int page, int size, String baseUrl) {
        LOGGER.debug("Find users by domain: {}", domain.getId());
        return userRepository.findByDomain(domain.getId(), page, size)
                .map(userPage -> {
                    // A negative value SHALL be interpreted as "0".
                    // A value of "0" indicates that no resource results are to be returned except for "totalResults".
                    if (size <= 0) {
                        return new ListResponse<User>(null, userPage.getCurrentPage() + 1, userPage.getTotalCount(), 0);
                    } else {
                        // SCIM use 1-based index (increment current page)
                        List<User> data = userPage.getData().stream().map(user1 -> convert(user1, baseUrl, true)).collect(Collectors.toList());
                        return new ListResponse<>(data, userPage.getCurrentPage() + 1, userPage.getTotalCount(), data.size());
                    }
                })
                .onErrorResumeNext(ex -> {
                    LOGGER.error("An error occurs while trying to find users by domain {}", domain, ex);
                    return Single.error(new TechnicalManagementException(String.format("An error occurs while trying to find users by domain %s", domain), ex));
                });
    }

    @Override
    public Maybe<User> get(String userId, String baseUrl) {
        LOGGER.debug("Find user by id : {}", userId);
        return userRepository.findById(userId)
                .map(user1 -> convert(user1, baseUrl, false))
                .flatMap(scimUser -> {
                    // fetch groups
                    return groupService.findByMember(scimUser.getId())
                            .map(groups -> {
                                if (!groups.isEmpty()) {
                                    List<Member> scimGroups = groups
                                            .stream()
                                            .map(group -> {
                                                Member member = new Member();
                                                member.setValue(group.getId());
                                                member.setDisplay(group.getDisplayName());
                                                return member;
                                            }).collect(Collectors.toList());
                                    scimUser.setGroups(scimGroups);
                                    return scimUser;
                                } else {
                                    return scimUser;
                                }
                            }).toMaybe();
                })
                .onErrorResumeNext(ex -> {
                    LOGGER.error("An error occurs while trying to find a user using its ID", userId, ex);
                    return Maybe.error(new TechnicalManagementException(
                            String.format("An error occurs while trying to find a user using its ID: %s", userId), ex));
                });
    }

    @Override
    public Single<User> create(User user, String baseUrl) {
        LOGGER.debug("Create a new user {} for domain {}", user.getUserName(), domain.getName());

        // check if user is unique
        return userRepository.findByUsernameAndDomain(domain.getId(), user.getUserName())
                .isEmpty()
                .map(isEmpty -> {
                    if (!isEmpty) {
                        throw new UniquenessException("User with username [" + user.getUserName()+ "] already exists");
                    }
                    return true;
                })
                .flatMap(irrelevant -> {
                    io.gravitee.am.model.User userModel = convert(user);
                    // set technical ID
                    userModel.setId(UUID.toString(UUID.random()));
                    userModel.setDomain(domain.getId());
                    userModel.setCreatedAt(new Date());
                    userModel.setUpdatedAt(userModel.getCreatedAt());
                    return userRepository.create(userModel);
                })
                .map(user1 -> convert(user1, baseUrl, true))
                .onErrorResumeNext(ex -> {
                    if (ex instanceof SCIMException) {
                        return Single.error(ex);
                    } else {
                        LOGGER.error("An error occurs while trying to create a user", ex);
                        return Single.error(new TechnicalManagementException("An error occurs while trying to create a user", ex));
                    }
                });
    }

    @Override
    public Single<User> update(User user, String baseUrl) {
        LOGGER.debug("Update a user {} for domain {}", user.getUserName(), domain.getName());
        return userRepository.findById(user.getId())
                .switchIfEmpty(Maybe.error(new UserNotFoundException(user.getId())))
                .flatMapSingle(existingUser -> userRepository.findByUsernameAndDomain(domain.getId(), user.getUserName())
                        .map(user1 -> {
                            // if username has changed check uniqueness
                            if (!existingUser.getId().equals(user1.getId())) {
                                throw new UniquenessException("User with username [" + user.getUserName()+ "] already exists");
                            }
                            return existingUser;
                        })
                        .flatMapSingle(user1 -> {
                            io.gravitee.am.model.User userToUpdate = convert(user);
                            // set immutable attribute
                            userToUpdate.setId(user1.getId());
                            userToUpdate.setDomain(user1.getDomain());
                            userToUpdate.setCreatedAt(user1.getCreatedAt());
                            userToUpdate.setUpdatedAt(new Date());
                            return userRepository.update(userToUpdate);
                        }))
                .map(user1 -> convert(user1, baseUrl, false))
                .onErrorResumeNext(ex -> {
                    if (ex instanceof AbstractManagementException || ex instanceof SCIMException) {
                        return Single.error(ex);
                    } else {
                        LOGGER.error("An error occurs while trying to update a user", ex);
                        return Single.error(new TechnicalManagementException("An error occurs while trying to update a user", ex));
                    }
                });
    }

    @Override
    public Completable delete(String userId) {
        LOGGER.debug("Delete user {}", userId);
        return userRepository.findById(userId)
                .switchIfEmpty(Maybe.error(new UserNotFoundException(userId)))
                .flatMapCompletable(user -> userRepository.delete(userId))
                .onErrorResumeNext(ex -> {
                    if (ex instanceof AbstractManagementException) {
                        return Completable.error(ex);
                    } else {
                        LOGGER.error("An error occurs while trying to delete user: {}", userId, ex);
                        return Completable.error(new TechnicalManagementException(
                                String.format("An error occurs while trying to delete user: %s", userId), ex));
                    }
                });
    }


    private User convert(io.gravitee.am.model.User user, String baseUrl, boolean listing) {
        Map<String, Object> additionalInformation = user.getAdditionalInformation() != null ? user.getAdditionalInformation() : Collections.emptyMap();

        User scimUser = new User();
        scimUser.setSchemas(User.SCHEMAS);
        scimUser.setId(user.getId());
        scimUser.setExternalId(get(additionalInformation, StandardClaims.SUB, String.class));
        scimUser.setUserName(user.getUsername());

        Name name = new Name();
        name.setGivenName(user.getFirstName());
        name.setFamilyName(user.getLastName());
        name.setMiddleName(get(additionalInformation, StandardClaims.MIDDLE_NAME, String.class));
        scimUser.setName(name);
        scimUser.setDisplayName(user.getDisplayName());
        scimUser.setNickName(user.getNickName());

        scimUser.setProfileUrl(get(additionalInformation, StandardClaims.PROFILE, String.class));
        scimUser.setTitle(user.getTitle());
        scimUser.setUserType(get(additionalInformation, UserClaims.USER_TYPE, String.class));
        scimUser.setPreferredLanguage(get(additionalInformation, UserClaims.PREFERRED_LANGUAGE, String.class));
        scimUser.setLocale(get(additionalInformation, StandardClaims.LOCALE, String.class));
        scimUser.setTimezone(get(additionalInformation, StandardClaims.ZONEINFO, String.class));
        scimUser.setActive(user.isEnabled());
        scimUser.setEmails(get(additionalInformation, UserClaims.EMAILS, List.class));
        scimUser.setPhoneNumbers(get(additionalInformation, UserClaims.PHONE_NUMBERS, List.class));
        scimUser.setIms(get(additionalInformation, UserClaims.IMS, List.class));
        scimUser.setPhotos(get(additionalInformation, UserClaims.PHOTOS, List.class));
        scimUser.setAddresses(get(additionalInformation, UserClaims.ADDRESSES, List.class));
        scimUser.setEntitlements(get(additionalInformation, UserClaims.ENTITLEMENTS, List.class));
        scimUser.setRoles(get(additionalInformation, UserClaims.ROLES, List.class));
        scimUser.setX509Certificates(get(additionalInformation, UserClaims.CERTIFICATES, List.class));

        // Meta
        Meta meta = new Meta();
        if (user.getCreatedAt() != null) {
            meta.setCreated(user.getCreatedAt().toInstant().toString());
        }
        if (user.getUpdatedAt() != null) {
            meta.setLastModified(user.getUpdatedAt().toInstant().toString());
        }
        meta.setResourceType(User.RESOURCE_TYPE);
        meta.setLocation(baseUrl + (listing ?  "/" + scimUser.getId() : ""));
        scimUser.setMeta(meta);
        return scimUser;
    }

    private io.gravitee.am.model.User convert(User scimUser) {
        io.gravitee.am.model.User user = new io.gravitee.am.model.User();
        Map<String, Object> additionalInformation = new HashMap();
        if (scimUser.getExternalId() != null) {
            additionalInformation.put(StandardClaims.SUB, scimUser.getExternalId());
        }
        user.setUsername(scimUser.getUserName());
        if (scimUser.getName() != null) {
            user.setFirstName(scimUser.getName().getGivenName());
            user.setLastName(scimUser.getName().getFamilyName());
            additionalInformation.put(StandardClaims.GIVEN_NAME, scimUser.getName().getGivenName());
            additionalInformation.put(StandardClaims.FAMILY_NAME, scimUser.getName().getFamilyName());
            additionalInformation.put(StandardClaims.MIDDLE_NAME, scimUser.getName().getMiddleName());
        }
        user.setDisplayName(scimUser.getDisplayName());
        user.setNickName(scimUser.getNickName());
        if (scimUser.getProfileUrl() != null) {
            additionalInformation.put(StandardClaims.PROFILE, scimUser.getProfileUrl());
        }
        user.setTitle(scimUser.getTitle());
        if (scimUser.getUserType() != null) {
            additionalInformation.put(UserClaims.USER_TYPE, scimUser.getUserType());
        }
        if (scimUser.getPreferredLanguage() != null) {
            additionalInformation.put(UserClaims.PREFERRED_LANGUAGE, scimUser.getPreferredLanguage());
        }
        if (scimUser.getLocale() != null) {
            additionalInformation.put(StandardClaims.LOCALE, scimUser.getLocale());
        }
        if (scimUser.getTimezone() != null) {
            additionalInformation.put(StandardClaims.ZONEINFO, scimUser.getTimezone());
        }
        // password
        // if not password set disable account
        if (user.getPassword() == null && (scimUser.getPassword() == null || scimUser.getPassword().isEmpty())) {
            user.setEnabled(false);
        }
        if (user.getPassword() == null && (scimUser.getPassword() != null && !scimUser.getPassword().isEmpty())) {
            user.setPassword(scimUser.getPassword());
            user.setEnabled(true);
        }
        // we do not allow to set null password
        if (user.getPassword() != null && (scimUser.getPassword() == null || scimUser.getPassword().isEmpty())) {
            user.setEnabled(user.isEnabled());
            user.setPassword(user.getPassword());
        }
        if (scimUser.getEmails() != null && !scimUser.getEmails().isEmpty()) {
            List<Attribute> emails = scimUser.getEmails();
            user.setEmail(emails.stream().filter(Attribute::isPrimary).findFirst().orElse(emails.get(0)).getValue());
            additionalInformation.put(UserClaims.EMAILS, emails);
        }
        if (scimUser.getPhoneNumbers() != null && !scimUser.getPhoneNumbers().isEmpty()) {
            additionalInformation.put(UserClaims.PHONE_NUMBERS, scimUser.getPhoneNumbers());
        }
        if (scimUser.getIms() != null && !scimUser.getIms().isEmpty()) {
            additionalInformation.put(UserClaims.IMS, scimUser.getIms());
        }
        if (scimUser.getPhotos() != null && !scimUser.getPhotos().isEmpty()) {
            List<Attribute> photos = scimUser.getPhotos();
            additionalInformation.put(StandardClaims.PICTURE, photos.stream().filter(Attribute::isPrimary).findFirst().orElse(photos.get(0)).getValue());
            additionalInformation.put(UserClaims.PHOTOS, photos);
        }
        if (scimUser.getAddresses() != null && !scimUser.getAddresses().isEmpty()) {
            additionalInformation.put(UserClaims.ADDRESSES, scimUser.getAddresses());
        }
        if (scimUser.getEntitlements() != null && !scimUser.getEntitlements().isEmpty()) {
            additionalInformation.put(UserClaims.ENTITLEMENTS, scimUser.getEntitlements());
        }
        if (scimUser.getRoles() != null && !scimUser.getRoles().isEmpty()) {
            additionalInformation.put(UserClaims.ROLES, scimUser.getRoles());
        }
        if (scimUser.getX509Certificates() != null && !scimUser.getX509Certificates().isEmpty()) {
            additionalInformation.put(UserClaims.CERTIFICATES, scimUser.getX509Certificates());
        }
        // set additional information
        user.setAdditionalInformation(additionalInformation);
        return user;
    }

    private <T> T get(Map<String, Object> additionalInformation, String key, Class<T> valueType) {
        if (!additionalInformation.containsKey(key)) {
            return null;
        }
        try {
            return (T) additionalInformation.get(key);
        } catch (ClassCastException e) {
            LOGGER.debug("An error occurs while retrieving {} information from user", key, e);
            return null;
        }
    }

}
