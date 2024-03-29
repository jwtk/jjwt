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
package io.jsonwebtoken.io;

import io.jsonwebtoken.lang.Assert;

/**
 * Very fast <a href="https://datatracker.ietf.org/doc/html/rfc4648#section-4">Base64</a> encoder guaranteed to
 * work in all &gt;= Java 7 JDK and Android environments.
 *
 * @since 0.10.0
 */
class Base64Encoder extends Base64Support implements Encoder<byte[], String> {

    Base64Encoder() {
        this(Base64.DEFAULT);
    }

    Base64Encoder(Base64 base64) {
        super(base64);
    }

    @Override
    public String encode(byte[] bytes) throws EncodingException {
        Assert.notNull(bytes, "byte array argument cannot be null");
        return this.base64.encodeToString(bytes, false);
    }
}
