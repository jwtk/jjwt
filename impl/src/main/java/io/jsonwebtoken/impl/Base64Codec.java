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
 * @deprecated since 0.10.0 - will be removed before 1.0.0. Use {@code io.jsonwebtoken.io.Encoders#BASE64}
 * or {@code io.jsonwebtoken.io.Decoders#BASE64}
 */
@Deprecated
public class Base64Codec extends AbstractTextCodec {

    public String encode(byte[] data) {
        return Encoders.BASE64.encode(data);
    }

    @Override
    public byte[] decode(String encoded) {
        return Decoders.BASE64.decode(encoded);
    }
}
