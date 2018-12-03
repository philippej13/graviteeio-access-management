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
package io.gravitee.am.management.handlers.management.api.resources;

import io.gravitee.am.model.PageType;
import io.gravitee.am.model.Template;
import io.gravitee.am.service.DomainService;
import io.gravitee.am.service.PageService;
import io.gravitee.am.service.exception.DomainNotFoundException;
import io.gravitee.am.service.model.NewPage;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.common.http.MediaType;
import io.reactivex.Maybe;
import io.swagger.annotations.*;
import org.springframework.beans.factory.annotation.Autowired;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import javax.ws.rs.*;
import javax.ws.rs.container.AsyncResponse;
import javax.ws.rs.container.ResourceContext;
import javax.ws.rs.container.Suspended;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import java.net.URI;

/**
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
@Api(tags = {"page"})
public class PagesResource extends AbstractResource {

    @Context
    private ResourceContext resourceContext;

    @Autowired
    private PageService pageService;

    @Autowired
    private DomainService domainService;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Find a page")
    @ApiResponses({
            @ApiResponse(code = 201, message = "Page successfully created"),
            @ApiResponse(code = 500, message = "Internal server error")})
    public void create(
            @PathParam("domain") String domain,
            @NotNull @QueryParam("type") PageType pageType,
            @NotNull  @QueryParam("template") Template pageTemplate,
            @Suspended final AsyncResponse response) {
        pageService.findByDomainAndTypeAndTemplate(domain, pageType.type(), pageTemplate.template())
                .map(page -> Response.ok(page).build())
                .defaultIfEmpty(Response.status(HttpStatusCode.NOT_FOUND_404).build())
                .subscribe(
                        result -> response.resume(result),
                        error -> response.resume(error));
    }

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Create a page")
    @ApiResponses({
            @ApiResponse(code = 201, message = "Page successfully created"),
            @ApiResponse(code = 500, message = "Internal server error")})
    public void create(
            @PathParam("domain") String domain,
            @ApiParam(name = "role", required = true)
            @Valid @NotNull final NewPage newPage,
            @Suspended final AsyncResponse response) {
        domainService.findById(domain)
                .switchIfEmpty(Maybe.error(new DomainNotFoundException(domain)))
                .flatMapSingle(irrelevant -> pageService.create(domain, newPage)
                            .map(role -> Response
                                    .created(URI.create("/domains/" + domain + "/pages/" + role.getId()))
                                    .entity(role)
                                    .build())
                )
                .subscribe(
                        result -> response.resume(result),
                        error -> response.resume(error));
    }

    @Path("{page}")
    public PageResource getPageResource() {
        return resourceContext.getResource(PageResource.class);
    }
}
