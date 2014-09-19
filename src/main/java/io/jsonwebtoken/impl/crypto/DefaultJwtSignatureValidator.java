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
import io.jsonwebtoken.impl.TextCodec;
import io.jsonwebtoken.lang.Assert;

import java.nio.charset.Charset;
import java.security.Key;

public class DefaultJwtSignatureValidator implements JwtSignatureValidator {

    private static final Charset US_ASCII = Charset.forName("US-ASCII");

    private final SignatureValidator signatureValidator;

    public DefaultJwtSignatureValidator(SignatureAlgorithm alg, Key key) {
        this(DefaultSignatureValidatorFactory.INSTANCE, alg, key);
    }

    public DefaultJwtSignatureValidator(SignatureValidatorFactory factory, SignatureAlgorithm alg, Key key) {
        Assert.notNull(factory, "SignerFactory argument cannot be null.");
        this.signatureValidator = factory.createSignatureValidator(alg, key);
    }

    @Override
    public boolean isValid(String jwtWithoutSignature, String base64UrlEncodedSignature) {

        byte[] data = jwtWithoutSignature.getBytes(US_ASCII);

        byte[] signature = TextCodec.BASE64URL.decode(base64UrlEncodedSignature);

        return this.signatureValidator.isValid(data, signature);
    }
}
