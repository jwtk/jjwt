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

import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;

/**
 * @deprecated since 0.10.0 - will be removed before 1.0.0. Use {@link Encoders#BASE64URL Encoder.BASE64URL}
 * or {@link Decoders#BASE64URL Decoder.BASE64URL} instead.
 */
@Deprecated
public class Base64UrlCodec extends AbstractTextCodec {

    @Override
    public String encode(byte[] data) {
        return Encoders.BASE64URL.encode(data);
    }

    @Override
    public byte[] decode(String encoded) {
        return Decoders.BASE64URL.decode(encoded);
    }
}
