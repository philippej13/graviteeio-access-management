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
import { Component, OnInit } from '@angular/core';

@Component({
  selector: 'app-domain-pages',
  templateUrl: './pages.component.html',
  styleUrls: ['./pages.component.scss']
})
export class DomainSettingsPagesComponent implements OnInit {
  pages: any[];
  domainId: string;

  constructor() { }


  ngOnInit() {
    this.pages = this.getPages();
  }

  get isEmpty() {
    return !this.pages || this.pages.length == 0;
  }

  getPages() {
    return [
      {
        'name': 'Login',
        'description': 'Login page to authenticate users',
        'type': 'HTML',
        'template': 'LOGIN'
      },
      {
        'name': 'Registration confirmation',
        'description': 'Register page to confirm user account',
        'type': 'HTML',
        'template': 'REGISTRATION_CONFIRMATION'
      },
      {
        'name': 'Forgot password',
        'description': 'Forgot password to recover account',
        'type': 'HTML',
        'template': 'FORGOT_PASSWORD'
      },
      {
        'name': 'Reset password',
        'description': 'Reset password page to make a new password',
        'type': 'HTML',
        'template': 'RESET_PASSWORD'
      },
    ]
  }
}
