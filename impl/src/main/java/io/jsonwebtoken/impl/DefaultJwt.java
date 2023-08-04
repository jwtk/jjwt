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
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Objects;

public class DefaultJwt<H extends Header, P> implements Jwt<H, P> {

    private final H header;
    private final P payload;

    public DefaultJwt(H header, P payload) {
        this.header = Assert.notNull(header, "header cannot be null.");
        this.payload = Assert.notNull(payload, "payload cannot be null.");
    }

    @Override
    public H getHeader() {
        return header;
    }

    @Override
    public P getBody() {
        return getPayload();
    }

    @Override
    public P getPayload() {
        return this.payload;
    }

    protected StringBuilder toStringBuilder() {
        StringBuilder sb = new StringBuilder(100);
        sb.append("header=").append(header).append(",payload=");
        if (payload instanceof byte[]) {
            String encoded = Encoders.BASE64URL.encode((byte[]) payload);
            sb.append(encoded);
        } else {
            sb.append(payload);
        }
        return sb;
    }

    @Override
    public final String toString() {
        return toStringBuilder().toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof Jwt) {
            Jwt<?, ?> jwt = (Jwt<?, ?>) obj;
            return Objects.nullSafeEquals(header, jwt.getHeader()) &&
                    Objects.nullSafeEquals(payload, jwt.getPayload());
        }
        return false;
    }

    @Override
    public int hashCode() {
        return Objects.nullSafeHashCode(header, payload);
    }
}
