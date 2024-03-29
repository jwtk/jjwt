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
 * Very fast <a href="https://datatracker.ietf.org/doc/html/rfc4648#section-4">Base64</a> decoder guaranteed to
 * work in all &gt;= Java 7 JDK and Android environments.
 *
 * @since 0.10.0
 */
class Base64Decoder extends Base64Support implements Decoder<CharSequence, byte[]> {

    Base64Decoder() {
        super(Base64.DEFAULT);
    }

    Base64Decoder(Base64 base64) {
        super(base64);
    }

    @Override
    public byte[] decode(CharSequence s) throws DecodingException {
        Assert.notNull(s, "String argument cannot be null");
        return this.base64.decodeFast(s);
    }
}