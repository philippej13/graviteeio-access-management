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
package io.gravitee.am.gateway.handler.page.impl;

import io.gravitee.am.gateway.core.event.PageEvent;
import io.gravitee.am.gateway.handler.page.PageManager;
import io.gravitee.am.gateway.handler.vertx.view.DomainBasedTemplateResolver;
import io.gravitee.am.model.Domain;
import io.gravitee.am.model.Page;
import io.gravitee.am.model.PageType;
import io.gravitee.am.model.common.event.Payload;
import io.gravitee.am.repository.management.api.PageRepository;
import io.gravitee.common.event.Event;
import io.gravitee.common.event.EventListener;
import io.gravitee.common.event.EventManager;
import io.gravitee.common.service.AbstractService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.thymeleaf.templateresolver.ITemplateResolver;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
public class PageManagerImpl extends AbstractService implements PageManager, InitializingBean, EventListener<PageEvent, Payload> {

    private static final Logger logger = LoggerFactory.getLogger(PageManagerImpl.class);
    private ConcurrentMap<String, Page> pages = new ConcurrentHashMap<>();

    @Autowired
    private ITemplateResolver templateResolver;

    @Autowired
    private PageRepository pageRepository;

    @Autowired
    private Domain domain;

    @Autowired
    private EventManager eventManager;

    @Override
    public void afterPropertiesSet() {
        logger.info("Initializing pages for domain {}", domain.getName());
        pageRepository.findByDomain(domain.getId())
                .subscribe(
                        pages -> {
                            updatePages(pages);
                            logger.info("Pages loaded for domain {}", domain.getName());
                        },
                        error -> logger.error("Unable to initialize pages for domain {}", domain.getName(), error));
    }

    @Override
    protected void doStart() throws Exception {
        super.doStart();

        logger.info("Register event listener for page events");
        eventManager.subscribeForEvents(this, PageEvent.class);
    }

    @Override
    public void onEvent(Event<PageEvent, Payload> event) {
        if (domain.getId().equals(event.content().getDomain())) {
            switch (event.type()) {
                case DEPLOY:
                case UPDATE:
                    updatePage(event.content().getId(), event.type());
                    break;
                case UNDEPLOY:
                    removePage(event.content().getId());
                    break;
            }
        }
    }

    private void updatePage(String pageId, PageEvent pageEvent) {
        final String eventType = pageEvent.toString().toLowerCase();
        logger.info("Domain {} has received {} page event for {}", domain.getName(), eventType, pageId);
        pageRepository.findById(pageId)
                .subscribe(
                        page -> {
                            // check if page has been disabled
                            if (pages.containsKey(pageId) && !page.isEnabled()) {
                                removePage(pageId);
                            } else {
                                updatePages(Collections.singletonList(page));
                            }
                            logger.info("Page {} {}d for domain {}", pageId, eventType, domain.getName());
                        },
                        error -> logger.error("Unable to {} page for domain {}", eventType, domain.getName(), error),
                        () -> logger.error("No page found with id {}", pageId));
    }

    private void removePage(String pageId) {
        logger.info("Domain {} has received page event, delete page {}", domain.getName(), pageId);
        Page deletedPaged = pages.remove(pageId);
        ((DomainBasedTemplateResolver) templateResolver).removePage(deletedPaged);
    }

    private void updatePages(List<Page> pages) {
        pages
                .stream()
                .filter(page -> page.isEnabled() && PageType.HTML.type().equals(page.getType()))
                .forEach(page -> {
                    this.pages.put(page.getId(), page);
                    ((DomainBasedTemplateResolver) templateResolver).addPage(page);
                    logger.info("Page {} loaded for domain {}", page.getTemplate(), domain.getName());
                });
    }
}
