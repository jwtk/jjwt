/*
 * Copyright (C) 2014 jsonwebtoken.io
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

import io.jsonwebtoken.Header;
import io.jsonwebtoken.Token;
import io.jsonwebtoken.lang.Assert;

public class DefaultToken<B> implements Token<B> {

    private final Header header;
    private final B body;
    private final String signature;

    public DefaultToken(Header header, B body, String signature) {
        this.header = header;
        this.body = body;
        this.signature = signature;
    }

    public boolean hasHeader() {
        return this.header != null;
    }

    public boolean isSigned() {
        return this.signature != null;
    }

    @Override
    public String getSignature() {
        Assert.notNull(signature, "Not a signed token.  Call 'isSigned()' before calling this method.");
        return this.signature;
    }

    @Override
    public Header getHeader() {
        Assert.notNull(header, "Header is not present.  Call 'hasHeader()' before calling this method.");
        return header;
    }

    @Override
    public B getBody() {
        return body;
    }
}
