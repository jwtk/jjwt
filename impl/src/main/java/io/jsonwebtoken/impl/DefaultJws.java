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
import io.jsonwebtoken.lang.Objects;

public class DefaultJws<B> extends DefaultJwt<JwsHeader, B> implements Jws<B> {

    private final String signature;

    public DefaultJws(JwsHeader header, B body, String signature) {
        super(header, body);
        this.signature = signature;
    }

    @Override
    public String getSignature() {
        return this.signature;
    }

    @Override
    public String toString() {
        return super.toString() + ",signature=" + signature;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof Jws) {
            Jws<?> jws = (Jws<?>) obj;
            return super.equals(jws) &&
                Objects.nullSafeEquals(signature, jws.getSignature());
        }
        return false;
    }

    @Override
    public int hashCode() {
        return Objects.nullSafeHashCode(getHeader(), getBody(), signature);
    }
}
