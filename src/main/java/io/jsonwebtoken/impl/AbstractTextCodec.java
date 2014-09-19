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

import io.jsonwebtoken.lang.Assert;

import java.nio.charset.Charset;

public abstract class AbstractTextCodec implements TextCodec {

    protected static final Charset UTF8     = Charset.forName("UTF-8");
    protected static final Charset US_ASCII = Charset.forName("US-ASCII");

    @Override
    public String encode(String data) {
        Assert.hasText(data, "String argument to encode cannot be null or empty.");
        byte[] bytes = data.getBytes(UTF8);
        return encode(bytes);
    }

    @Override
    public String decodeToString(String encoded) {
        byte[] bytes = decode(encoded);
        return new String(bytes, UTF8);
    }
}
