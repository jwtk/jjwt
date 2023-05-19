/*
 * Copyright (C) 2021 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.jsonwebtoken.impl;

import io.jsonwebtoken.JweHeaderBuilder;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class DefaultJweHeaderBuilder extends AbstractProtectedHeaderBuilder<DefaultJweHeader, JweHeaderBuilder>
   implements JweHeaderBuilder {

    @Override
    protected DefaultJweHeader newHeader() {
        return new DefaultJweHeader();
    }

    @Override
    public JweHeaderBuilder setAgreementPartyUInfo(byte[] info) {
        this.header.setAgreementPartyUInfo(info);
        return this;
    }

    @Override
    public JweHeaderBuilder setAgreementPartyUInfo(String info) {
        this.header.setAgreementPartyUInfo(info);
        return this;
    }

    @Override
    public JweHeaderBuilder setAgreementPartyVInfo(byte[] info) {
        this.header.setAgreementPartyVInfo(info);
        return this;
    }

    @Override
    public JweHeaderBuilder setAgreementPartyVInfo(String info) {
        this.header.setAgreementPartyVInfo(info);
        return this;
    }

    @Override
    public JweHeaderBuilder setPbes2Count(int count) {
        this.header.setPbes2Count(count);
        return this;
    }
}
