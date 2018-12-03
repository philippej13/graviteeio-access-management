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
package io.gravitee.am.management.service.impl.upgrades;

import io.gravitee.am.model.Domain;
import io.gravitee.am.model.PageType;
import io.gravitee.am.model.Template;
import io.gravitee.am.service.DomainService;
import io.gravitee.am.service.PageService;
import io.gravitee.am.service.model.NewPage;
import io.reactivex.Observable;
import io.reactivex.Single;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;

/**
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
@Component
public class DomainLoginFormUpgrader implements Upgrader, Ordered {

    private static final Logger logger = LoggerFactory.getLogger(OpenIDScopeUpgrader.class);

    @Autowired
    private DomainService domainService;

    @Autowired
    private PageService pageService;

    @Override
    public boolean upgrade() {
        logger.info("Applying domain login form upgrade");
        domainService.findAll()
                .flatMapObservable(Observable::fromIterable)
                .filter(domain -> domain.getLoginForm() != null)
                .flatMapSingle(this::updateLoginPage)
                .subscribe();

        return true;
    }

    private Single<Domain> updateLoginPage(Domain domain) {
        logger.info("Move login form to pages collection for domain [{}]", domain.getName());
        NewPage newPage = new NewPage();
        newPage.setType(PageType.HTML);
        newPage.setTemplate(Template.LOGIN);
        newPage.setContent(domain.getLoginForm().getContent());
        newPage.setEnabled(domain.getLoginForm().isEnabled());

        return pageService.create(domain.getId(), newPage)
                .flatMap(page -> domainService.deleteLoginForm(domain.getId()));  // remove login form from domain object
    }

    @Override
    public int getOrder() {
        return 163;
    }
}
