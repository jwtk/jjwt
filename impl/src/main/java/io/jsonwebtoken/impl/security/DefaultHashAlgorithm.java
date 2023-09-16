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
package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.HashAlgorithm;
import io.jsonwebtoken.security.Request;
import io.jsonwebtoken.security.VerifyDigestRequest;

import java.security.MessageDigest;
import java.util.Locale;

public final class DefaultHashAlgorithm extends CryptoAlgorithm implements HashAlgorithm {

    public static final HashAlgorithm SHA1 = new DefaultHashAlgorithm("sha-1");

    DefaultHashAlgorithm(String id) {
        super(id, id.toUpperCase(Locale.ENGLISH));
    }

    @Override
    public byte[] digest(final Request<byte[]> request) {
        Assert.notNull(request, "Request cannot be null.");
        final byte[] payload = Assert.notNull(request.getPayload(), "Request payload cannot be null.");
        return jca(request).withMessageDigest(new CheckedFunction<MessageDigest, byte[]>() {
            @Override
            public byte[] apply(MessageDigest md) {
                return md.digest(payload);
            }
        });
    }

    @Override
    public boolean verify(VerifyDigestRequest request) {
        Assert.notNull(request, "VerifyDigestRequest cannot be null.");
        byte[] digest = Assert.notNull(request.getDigest(), "Digest cannot be null.");
        byte[] computed = digest(request);
        return MessageDigest.isEqual(computed, digest); // time-constant comparison required, not standard equals
    }
}
