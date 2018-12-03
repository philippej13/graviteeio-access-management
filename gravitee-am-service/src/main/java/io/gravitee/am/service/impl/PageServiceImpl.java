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
package io.gravitee.am.service.impl;

import io.gravitee.am.model.Page;
import io.gravitee.am.model.common.event.Action;
import io.gravitee.am.model.common.event.Event;
import io.gravitee.am.model.common.event.Payload;
import io.gravitee.am.model.common.event.Type;
import io.gravitee.am.repository.management.api.PageRepository;
import io.gravitee.am.service.DomainService;
import io.gravitee.am.service.PageService;
import io.gravitee.am.service.exception.AbstractManagementException;
import io.gravitee.am.service.exception.PageAlreadyExistsException;
import io.gravitee.am.service.exception.PageNotFoundException;
import io.gravitee.am.service.exception.TechnicalManagementException;
import io.gravitee.am.service.model.NewPage;
import io.gravitee.am.service.model.UpdatePage;
import io.gravitee.common.utils.UUID;
import io.reactivex.Completable;
import io.reactivex.Maybe;
import io.reactivex.Single;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Date;

/**
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
@Component
public class PageServiceImpl implements PageService {

    private final Logger LOGGER = LoggerFactory.getLogger(PageServiceImpl.class);

    @Autowired
    private PageRepository pageRepository;

    @Autowired
    private DomainService domainService;

    @Override
    public Maybe<Page> findByDomainAndTypeAndTemplate(String domain, String type, String template) {
        LOGGER.debug("Find page by domain {}, type {} and template {}", domain, type, template);
        return pageRepository.findByDomainAndTypeAndTemplate(domain, type, template)
                .onErrorResumeNext(ex -> {
                    LOGGER.error("An error occurs while trying to find a page using its domain {}, type {} and template {}", domain, type, template, ex);
                    return Maybe.error(new TechnicalManagementException(
                            String.format("An error occurs while trying to find a role using its domain %s, type %s and template %s", domain, type, template), ex));
                });
    }

    @Override
    public Maybe<Page> findByDomainAndClientAndTypeAndTemplate(String domain, String client, String type, String template) {
        LOGGER.debug("Find page by domain {}, client {},  type {} and template {}", domain, client, type, template);
        return pageRepository.findByDomainAndClientAndTypeAndTemplate(domain, client, type, template)
                .onErrorResumeNext(ex -> {
                    LOGGER.error("An error occurs while trying to find a page using its domain {}, client {}, type {} and template {}", domain, client, type, template, ex);
                    return Maybe.error(new TechnicalManagementException(
                            String.format("An error occurs while trying to find a role using its domain %s, client %s, type %s and template %s", domain, client, type, template), ex));
                });
    }

    @Override
    public Single<Page> create(String domain, NewPage newPage) {
        LOGGER.debug("Create a new page {} for domain {}", newPage, domain);

        String pageId = UUID.toString(UUID.random());

        // check if page is unique
        return checkPageUniqueness(domain, newPage.getType().type(), newPage.getTemplate().template())
                .flatMap(irrelevant -> {
                    Page page = new Page();
                    page.setId(pageId);
                    page.setDomain(domain);
                    page.setEnabled(newPage.isEnabled());
                    page.setTemplate(newPage.getTemplate().template());
                    page.setType(newPage.getType().type());
                    page.setContent(newPage.getContent());
                    page.setAssets(newPage.getAssets());
                    page.setCreatedAt(new Date());
                    page.setUpdatedAt(page.getCreatedAt());
                    return pageRepository.create(page);
                })
                .flatMap(page -> {
                    // Reload domain to take care about page creation
                    Event event = new Event(Type.PAGE, new Payload(page.getId(), page.getDomain(), Action.CREATE));
                    return domainService.reload(domain, event).flatMap(domain1 -> Single.just(page));
                })
                .onErrorResumeNext(ex -> {
                    if (ex instanceof AbstractManagementException) {
                        return Single.error(ex);
                    }

                    LOGGER.error("An error occurs while trying to create a page", ex);
                    return Single.error(new TechnicalManagementException("An error occurs while trying to create a page", ex));
                });
    }

    @Override
    public Single<Page> update(String domain, String id, UpdatePage updatePage) {
        LOGGER.debug("Update a page {} for domain {}", id, domain);
        return pageRepository.findById(id)
                .switchIfEmpty(Maybe.error(new PageNotFoundException(id)))
                .flatMapSingle(oldPage -> {
                    oldPage.setEnabled(updatePage.isEnabled());
                    oldPage.setContent(updatePage.getContent());
                    oldPage.setAssets(updatePage.getAssets());
                    oldPage.setUpdatedAt(new Date());

                    return pageRepository.update(oldPage);
                })
                .flatMap(page -> {
                    // Reload domain to take care about page update
                    Event event = new Event(Type.PAGE, new Payload(page.getId(), page.getDomain(), Action.UPDATE));
                    return domainService.reload(domain, event).flatMap(domain1 -> Single.just(page));
                })
                .onErrorResumeNext(ex -> {
                    if (ex instanceof AbstractManagementException) {
                        return Single.error(ex);
                    }

                    LOGGER.error("An error occurs while trying to update a page", ex);
                    return Single.error(new TechnicalManagementException("An error occurs while trying to update a page", ex));
                });
    }

    @Override
    public Completable delete(String pageId) {
        LOGGER.debug("Delete role {}", pageId);
        return pageRepository.findById(pageId)
                .switchIfEmpty(Maybe.error(new PageNotFoundException(pageId)))
                .flatMapCompletable(page -> {
                    // Reload domain to take care about delete page
                    Event event = new Event(Type.PAGE, new Payload(page.getId(), page.getDomain(), Action.DELETE));
                    return pageRepository.delete(pageId).andThen(domainService.reload(page.getDomain(), event)).toCompletable();
                })
                .onErrorResumeNext(ex -> {
                    if (ex instanceof AbstractManagementException) {
                        return Completable.error(ex);
                    }

                    LOGGER.error("An error occurs while trying to delete page: {}", pageId, ex);
                    return Completable.error(new TechnicalManagementException(
                            String.format("An error occurs while trying to delete page: %s", pageId), ex));
                });
    }

    private Single<Boolean> checkPageUniqueness(String domain, String pageType, String pageTemplate) {
        return findByDomainAndTypeAndTemplate(domain, pageType, pageTemplate)
                .isEmpty()
                .map(isEmpty -> {
                    if (!isEmpty) {
                        throw new PageAlreadyExistsException(pageType, pageTemplate);
                    }
                    return true;
                });
    }
}
