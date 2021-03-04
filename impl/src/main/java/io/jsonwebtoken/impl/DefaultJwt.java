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
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Objects;

public class DefaultJwt<H extends Header<H>, B> implements Jwt<H,B> {

    private final H header;
    private final B body;

    public DefaultJwt(H header, B body) {
        this.header = Assert.notNull(header, "header cannot be null.");
        this.body = Assert.notNull(body, "body cannot be null.");
    }

    @Override
    public H getHeader() {
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

    @Override
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof Jwt) {
            Jwt<?, ?> jwt = (Jwt<?,?>)obj;
            return Objects.nullSafeEquals(header, jwt.getHeader()) &&
                Objects.nullSafeEquals(body, jwt.getBody());
        }
        return false;
    }

    @Override
    public int hashCode() {
        return Objects.nullSafeHashCode(header, body);
    }
}
