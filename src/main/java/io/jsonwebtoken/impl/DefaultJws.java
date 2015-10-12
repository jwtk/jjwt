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

import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;

public class DefaultJws<B> implements Jws<B> {

    private final JwsHeader header;
    private final B body;
    private final String signature;

    public DefaultJws(JwsHeader header, B body, String signature) {
        this.header = header;
        this.body = body;
        this.signature = signature;
    }

    @Override
    public JwsHeader getHeader() {
        return this.header;
    }

    @Override
    public B getBody() {
        return this.body;
    }

    @Override
    public String getSignature() {
        return this.signature;
    }

    @Override
    public String toString() {
        return "header=" + header + ",body=" + body + ",signature=" + signature;
    }
}
