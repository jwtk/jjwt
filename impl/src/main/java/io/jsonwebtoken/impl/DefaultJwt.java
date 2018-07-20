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
import io.jsonwebtoken.Jwt;

public class DefaultJwt<B> implements Jwt<Header,B> {

    private final Header header;
    private final B body;

    public DefaultJwt(Header header, B body) {
        this.header = header;
        this.body = body;
    }

    @Override
    public Header getHeader() {
        return header;
    }

    @Override
    public B getBody() {
        return body;
    }

    @Override
    public String toString() {
        return "header=" + header + ",body=" + body;
    }
}
