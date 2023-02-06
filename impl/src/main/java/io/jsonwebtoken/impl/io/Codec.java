/*
 * Copyright © 2021 jsonwebtoken.io
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
package io.jsonwebtoken.impl.io;

import io.jsonwebtoken.impl.lang.Converter;
import io.jsonwebtoken.io.Decoder;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.DecodingException;
import io.jsonwebtoken.io.Encoder;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.lang.Assert;

public class Codec implements Converter<byte[], String> {

    public static final Codec BASE64 = new Codec(Encoders.BASE64, Decoders.BASE64);
    public static final Codec BASE64URL = new Codec(Encoders.BASE64URL, Decoders.BASE64URL);

    private final Encoder<byte[], String> encoder;
    private final Decoder<String, byte[]> decoder;

    public Codec(Encoder<byte[], String> encoder, Decoder<String, byte[]> decoder) {
        this.encoder = Assert.notNull(encoder, "Encoder cannot be null.");
        this.decoder = Assert.notNull(decoder, "Decoder cannot be null.");
    }

    @Override
    public String applyTo(byte[] a) {
        return this.encoder.encode(a);
    }

    @Override
    public byte[] applyFrom(String b) {
        try {
            return this.decoder.decode(b);
        } catch (DecodingException e) {
            String msg = "Cannot decode input String. Cause: " + e.getMessage();
            throw new IllegalArgumentException(msg, e);
        }
    }
}
