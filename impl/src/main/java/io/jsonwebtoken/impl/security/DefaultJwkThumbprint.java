/*
 * Copyright (C) 2022 jsonwebtoken.io
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
package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.HashAlgorithm;
import io.jsonwebtoken.security.JwkThumbprint;

import java.net.URI;
import java.security.MessageDigest;

class DefaultJwkThumbprint implements JwkThumbprint {

    private static final String URI_PREFIX = "urn:ietf:params:oauth:jwk-thumbprint:";

    private final byte[] digest;
    private final HashAlgorithm alg;
    private final URI uri;
    private final int hashcode;
    private final String sval;

    DefaultJwkThumbprint(byte[] digest, HashAlgorithm alg) {
        this.digest = Assert.notEmpty(digest, "Thumbprint digest byte array cannot be null or empty.");
        this.alg = Assert.notNull(alg, "Thumbprint HashAlgorithm cannot be null.");
        String id = Assert.hasText(Strings.clean(alg.getId()), "Thumbprint HashAlgorithm id cannot be null or empty.");
        String base64Url = Encoders.BASE64URL.encode(digest);
        String s = URI_PREFIX + id + ":" + base64Url;
        this.uri = URI.create(s);
        this.hashcode = Objects.nullSafeHashCode(this.digest, this.alg);
        this.sval = Encoders.BASE64URL.encode(digest);
    }

    @Override
    public HashAlgorithm getHashAlgorithm() {
        return this.alg;
    }

    @Override
    public byte[] toByteArray() {
        return this.digest.clone();
    }

    @Override
    public URI toURI() {
        return this.uri;
    }

    @Override
    public String toString() {
        return sval;
    }

    @Override
    public int hashCode() {
        return this.hashcode;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof DefaultJwkThumbprint) {
            DefaultJwkThumbprint other = (DefaultJwkThumbprint) obj;
            return this.alg.equals(other.alg) &&
                    MessageDigest.isEqual(this.digest, other.digest);
        }

        return false;
    }
}
