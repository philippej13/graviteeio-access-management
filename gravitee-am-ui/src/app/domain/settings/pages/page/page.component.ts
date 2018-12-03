/*
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
import {AfterViewInit, Component, ElementRef, Inject, OnInit, ViewChild} from "@angular/core";
import { ActivatedRoute, Router } from "@angular/router";
import { BreadcrumbService } from "../../../../../libraries/ng2-breadcrumb/components/breadcrumbService";
import { AppConfig } from "../../../../../config/app.config";
import { PageService } from "../../../../services/page.service";
import { SnackbarService } from "../../../../services/snackbar.service";
import { DialogService } from "../../../../services/dialog.service";
import {MAT_DIALOG_DATA, MatDialog, MatDialogRef} from "@angular/material";

export interface DialogData {
  rawTemplate: string;
  template: string;
}

@Component({
  selector: 'app-page',
  templateUrl: './page.component.html',
  styleUrls: ['./page.component.scss']
})
export class PageComponent implements OnInit, AfterViewInit {
  private domainId: string;
  private defaultPageContent: string = `// Custom form...`;
  private pageType: string;
  template: string;
  rawTemplate: string;
  page: any;
  pageName: string;
  pageContent: string = (' ' + this.defaultPageContent).slice(1);
  originalPageContent: string = (' ' + this.pageContent).slice(1);
  pageFound: boolean = false;
  formChanged: boolean = false;
  config: any = { lineNumbers: true, readOnly: true};
  @ViewChild('editor') editor: any;
  @ViewChild('preview') preview: ElementRef;

  constructor(private router: Router,
              private route: ActivatedRoute,
              private breadcrumbService: BreadcrumbService,
              private pageService: PageService,
              private snackbarService: SnackbarService,
              private dialogService: DialogService,
              public dialog: MatDialog) { }

  ngOnInit() {
    this.domainId = this.route.snapshot.parent.parent.params['domainId'];
    if (this.router.routerState.snapshot.url.startsWith('/settings')) {
      this.domainId = AppConfig.settings.authentication.domainId;
      this.rawTemplate = 'LOGIN';
      this.pageType = 'HTML';
    } else {
      this.rawTemplate = this.route.snapshot.queryParams['template'];
      this.pageType = this.route.snapshot.queryParams['type']
    }

    this.page = this.route.snapshot.data['page'];
    if (this.page && this.page.content) {
      this.pageContent = this.page.content;
      this.originalPageContent = (' ' + this.originalPageContent).slice(1);
      this.pageFound = true;
    } else {
      this.page = {};
      this.page.type = this.pageType;
      this.page.template = this.rawTemplate
    }

    this.template = this.rawTemplate.toLowerCase().replace(/_/g, ' ');;
    this.pageName = this.template.charAt(0).toUpperCase() + this.template.slice(1);
    this.initBreadcrumb();
  }

  ngAfterViewInit(): void {
    this.enableCodeMirror();
  }

  initBreadcrumb() {
    this.breadcrumbService.addFriendlyNameForRouteRegex('/domains/'+this.domainId+'/settings/pages/page*', this.template);
  }

  isEnabled() {
    return this.page && this.page.enabled;
  }

  enablePage(event) {
    this.page.enabled = event.checked;
    this.enableCodeMirror();
    this.formChanged = true;
  }

  onTabSelectedChanged(e) {
    if (e.index === 1) {
      this.refreshPreview();
    }
  }

  refreshPreview() {
    let doc =  this.preview.nativeElement.contentDocument || this.preview.nativeElement.contentWindow;
    doc.open();
    doc.write(this.pageContent);
    doc.close();
  }

  onContentChanges(e) {
    if (e !== this.originalPageContent) {
      this.formChanged = true;
    }
  }

  resizeIframe() {
    this.preview.nativeElement.style.height = this.preview.nativeElement.contentWindow.document.body.scrollHeight + 'px';
  }

  create() {
    this.page['content'] = this.pageContent;
    this.pageService.create(this.domainId, this.page).map(res => res.json()).subscribe(data => {
      this.snackbarService.open("Page created");
      this.pageFound = true;
      this.page = data;
      this.formChanged = false;
    })
  }

  update() {
    this.page['content'] = this.pageContent;
    this.pageService.update(this.domainId, this.page.id, this.page).map(res => res.json()).subscribe(data => {
      this.snackbarService.open("Page updated");
      this.pageFound = true;
      this.page = data;
      this.formChanged = false;
    })
  }

  delete(event) {
    event.preventDefault();
    this.dialogService
      .confirm('Delete page', 'Are you sure you want to delete this page ?')
      .subscribe(res => {
        if (res) {
          this.pageService.delete(this.domainId, this.page.id).subscribe(response => {
            this.snackbarService.open("Page deleted");
            this.page = {};
            this.page.type = this.route.snapshot.queryParams['type'];
            this.page.template = this.route.snapshot.queryParams['template'];
            this.pageContent =  (' ' + this.defaultPageContent).slice(1);
            this.pageFound = false;
            this.enableCodeMirror();
          });
        }
      });
  }

  openDialog() {
    this.dialog.open(PageInfoDialog, {
      data: {rawTemplate: this.rawTemplate, template: this.template}
    });
  }

  private enableCodeMirror(): void {
    this.editor.instance.setOption('readOnly', !this.page.enabled);
  }
}

@Component({
  selector: 'page-info-dialog',
  templateUrl: './dialog/page-info.component.html',
})
export class PageInfoDialog {
  constructor(public dialogRef: MatDialogRef<PageInfoDialog>, @Inject(MAT_DIALOG_DATA) public data: DialogData) {}
}
