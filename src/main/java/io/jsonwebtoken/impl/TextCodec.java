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

/**
 * @deprecated since 0.10.0.  Use an {@link io.jsonwebtoken.codec.Encoder} or {@link io.jsonwebtoken.codec.Decoder}
 * as needed.  This class will be removed before 1.0.0
 */
@Deprecated
public interface TextCodec {

    /**
     * @deprecated since 0.10.0.  Use {@link io.jsonwebtoken.codec.Encoder#BASE64 Encoder.BASE64} or
     * {@link io.jsonwebtoken.codec.Decoder#BASE64 Decoder.BASE64} instead. This class will be removed before 1.0.0
     */
    @Deprecated
    TextCodec BASE64 = new Base64Codec();

    /**
     * @deprecated since 0.10.0.  Use {@link io.jsonwebtoken.codec.Encoder#BASE64URL Encoder.BASE64URL} or
     * {@link io.jsonwebtoken.codec.Decoder#BASE64URL Decoder.BASE64URL} instead. This class will be removed before 1.0.0
     */
    @Deprecated
    TextCodec BASE64URL = new Base64UrlCodec();

    String encode(String data);

    String encode(byte[] data);

    byte[] decode(String encoded);

    String decodeToString(String encoded);
}
