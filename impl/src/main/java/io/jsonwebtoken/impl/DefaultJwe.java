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

import io.jsonwebtoken.Jwe;
import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Objects;

public class DefaultJwe<P> extends DefaultJwt<JweHeader, P> implements Jwe<P> {

    private final byte[] iv;
    private final byte[] aadTag;

    public DefaultJwe(JweHeader header, P body, byte[] iv, byte[] aadTag) {
        super(header, body);
        this.iv = Assert.notEmpty(iv, "Initialization vector cannot be null or empty.");
        this.aadTag = Assert.notEmpty(aadTag, "AAD tag cannot be null or empty.");
    }

    @Override
    public byte[] getInitializationVector() {
        return this.iv;
    }

    @Override
    public byte[] getAadTag() {
        return this.aadTag;
    }

    @Override
    protected StringBuilder toStringBuilder() {
        StringBuilder sb = super.toStringBuilder();
        sb.append(",iv=").append(Encoders.BASE64URL.encode(this.iv));
        sb.append(",tag=").append(Encoders.BASE64URL.encode(this.aadTag));
        return sb;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof Jwe) {
            Jwe<?> jwe = (Jwe<?>) obj;
            return super.equals(jwe) &&
                    Objects.nullSafeEquals(iv, jwe.getInitializationVector()) &&
                    Objects.nullSafeEquals(aadTag, jwe.getAadTag());
        }
        return false;
    }

    @Override
    public int hashCode() {
        return Objects.nullSafeHashCode(getHeader(), getPayload(), iv, aadTag);
    }
}
