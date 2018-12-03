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
package io.gravitee.am.repository.mongodb.management;

import com.mongodb.reactivestreams.client.MongoCollection;
import io.gravitee.am.model.Page;
import io.gravitee.am.repository.management.api.PageRepository;
import io.gravitee.am.repository.mongodb.common.IdGenerator;
import io.gravitee.am.repository.mongodb.common.LoggableIndexSubscriber;
import io.gravitee.am.repository.mongodb.management.internal.model.PageMongo;
import io.reactivex.Completable;
import io.reactivex.Maybe;
import io.reactivex.Observable;
import io.reactivex.Single;
import org.bson.Document;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.List;

import static com.mongodb.client.model.Filters.and;
import static com.mongodb.client.model.Filters.eq;

/**
 * @author Titouan COMPIEGNE (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
@Component
public class MongoPageRepository extends AbstractManagementMongoRepository implements PageRepository {

    private static final String FIELD_ID = "_id";
    private static final String FIELD_DOMAIN = "domain";
    private static final String FIELD_CLIENT = "client";
    private static final String FIELD_TYPE = "type";
    private static final String FIELD_TEMPLATE = "template";
    private MongoCollection<PageMongo> pagesCollection;

    @PostConstruct
    public void init() {
        pagesCollection = mongoOperations.getCollection("pages", PageMongo.class);
        pagesCollection.createIndex(new Document(FIELD_DOMAIN, 1)).subscribe(new LoggableIndexSubscriber());
        pagesCollection.createIndex(new Document(FIELD_DOMAIN, 1).append(FIELD_CLIENT, 1)).subscribe(new LoggableIndexSubscriber());
        pagesCollection.createIndex(new Document(FIELD_DOMAIN, 1).append(FIELD_TYPE, 1)).subscribe(new LoggableIndexSubscriber());
        pagesCollection.createIndex(new Document(FIELD_DOMAIN, 1).append(FIELD_TYPE, 1).append(FIELD_TEMPLATE, 1)).subscribe(new LoggableIndexSubscriber());
        pagesCollection.createIndex(new Document(FIELD_DOMAIN, 1).append(FIELD_CLIENT, 1).append(FIELD_TYPE, 1)).subscribe(new LoggableIndexSubscriber());
        pagesCollection.createIndex(new Document(FIELD_DOMAIN, 1).append(FIELD_CLIENT, 1).append(FIELD_TYPE, 1).append(FIELD_TEMPLATE, 1)).subscribe(new LoggableIndexSubscriber());
    }

    @Autowired
    private IdGenerator idGenerator;

    @Override
    public Single<List<Page>> findByDomain(String domain) {
        return Observable.fromPublisher(pagesCollection.find(eq(FIELD_DOMAIN, domain))).map(this::convert).collect(ArrayList::new, List::add);
    }

    @Override
    public Maybe<Page> findByDomainAndTypeAndTemplate(String domain, String type, String template) {
        return Observable.fromPublisher(
                pagesCollection.find(
                        and(
                                eq(FIELD_DOMAIN, domain),
                                eq(FIELD_TYPE, type),
                                eq(FIELD_TEMPLATE, template)))
                        .first())
                .firstElement().map(this::convert);
    }

    @Override
    public Maybe<Page> findByDomainAndClientAndTypeAndTemplate(String domain, String client, String type, String template) {
        return Observable.fromPublisher(
                pagesCollection.find(
                        and(
                                eq(FIELD_DOMAIN, domain),
                                eq(FIELD_CLIENT, client),
                                eq(FIELD_TYPE, type),
                                eq(FIELD_TEMPLATE, template)))
                        .first())
                .firstElement().map(this::convert);
    }

    @Override
    public Maybe<Page> findById(String page) {
        return Observable.fromPublisher(pagesCollection.find(eq(FIELD_ID, page)).first()).firstElement().map(this::convert);
    }

    @Override
    public Single<Page> create(Page item) {
        PageMongo page = convert(item);
        page.setId(page.getId() == null ? (String) idGenerator.generate() : page.getId());
        return Single.fromPublisher(pagesCollection.insertOne(page)).flatMap(success -> findById(page.getId()).toSingle());
    }

    @Override
    public Single<Page> update(Page item) {
        PageMongo page = convert(item);
        return Single.fromPublisher(pagesCollection.replaceOne(eq(FIELD_ID, page.getId()), page)).flatMap(updateResult -> findById(page.getId()).toSingle());
    }

    @Override
    public Completable delete(String id) {
        return Completable.fromPublisher(pagesCollection.deleteOne(eq(FIELD_ID, id)));
    }

    private Page convert(PageMongo pageMongo) {
        if (pageMongo == null) {
            return null;
        }
        Page page = new Page();
        page.setId(pageMongo.getId());
        page.setEnabled(pageMongo.isEnabled());
        page.setDomain(pageMongo.getDomain());
        page.setClient(pageMongo.getClient());
        page.setTemplate(pageMongo.getTemplate());
        page.setType(pageMongo.getType());
        page.setContent(pageMongo.getContent());
        page.setAssets(pageMongo.getAssets());
        page.setCreatedAt(pageMongo.getCreatedAt());
        page.setUpdatedAt(pageMongo.getUpdatedAt());
        return page;
    }

    private PageMongo convert(Page page) {
        if (page == null) {
            return null;
        }

        PageMongo pageMongo = new PageMongo();
        pageMongo.setId(page.getId());
        pageMongo.setEnabled(page.isEnabled());
        pageMongo.setDomain(page.getDomain());
        pageMongo.setClient(page.getClient());
        pageMongo.setTemplate(page.getTemplate());
        pageMongo.setType(page.getType());
        pageMongo.setContent(page.getContent());
        pageMongo.setAssets(page.getAssets());
        pageMongo.setCreatedAt(page.getCreatedAt());
        pageMongo.setUpdatedAt(page.getUpdatedAt());
        return pageMongo;
    }
}
