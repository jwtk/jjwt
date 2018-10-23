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
package io.jsonwebtoken.impl.crypto;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Encoder;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.lang.Assert;

import java.nio.charset.Charset;
import java.security.Key;

public class DefaultJwtSigner implements JwtSigner {

    private static final Charset US_ASCII = Charset.forName("US-ASCII");

    private final Signer signer;
    private final Encoder<byte[], String> base64UrlEncoder;

    @Deprecated
    public DefaultJwtSigner(SignatureAlgorithm alg, Key key) {
        this(DefaultSignerFactory.INSTANCE, alg, key, Encoders.BASE64URL);
    }

    public DefaultJwtSigner(SignatureAlgorithm alg, Key key, Encoder<byte[], String> base64UrlEncoder) {
        this(DefaultSignerFactory.INSTANCE, alg, key, base64UrlEncoder);
    }

    @Deprecated
    public DefaultJwtSigner(SignerFactory factory, SignatureAlgorithm alg, Key key) {
        this(factory, alg, key, Encoders.BASE64URL);
    }

    public DefaultJwtSigner(SignerFactory factory, SignatureAlgorithm alg, Key key, Encoder<byte[], String> base64UrlEncoder) {
        Assert.notNull(factory, "SignerFactory argument cannot be null.");
        Assert.notNull(base64UrlEncoder, "Base64Url Encoder cannot be null.");
        this.base64UrlEncoder = base64UrlEncoder;
        this.signer = factory.createSigner(alg, key);
    }

    @Override
    public String sign(String jwtWithoutSignature) {

        byte[] bytesToSign = jwtWithoutSignature.getBytes(US_ASCII);

        byte[] signature = signer.sign(bytesToSign);

        return base64UrlEncoder.encode(signature);
    }
}
