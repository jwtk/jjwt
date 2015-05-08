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
import io.jsonwebtoken.lang.Assert;

import java.security.Key;

public class DefaultSignerFactory implements SignerFactory {

    public static final SignerFactory INSTANCE = new DefaultSignerFactory();

    @Override
    public Signer createSigner(SignatureAlgorithm alg, Key key) {
        Assert.notNull(alg, "SignatureAlgorithm cannot be null.");
        Assert.notNull(key, "Signing Key cannot be null.");

        switch (alg) {
            case HS256:
            case HS384:
            case HS512:
                return new MacSigner(alg, key);
            case RS256:
            case RS384:
            case RS512:
            case PS256:
            case PS384:
            case PS512:
                return new RsaSigner(alg, key);
            case ES256:
            case ES384:
            case ES512:
                return new EllipticCurveSigner(alg, key);
            default:
                throw new IllegalArgumentException("The '" + alg.name() + "' algorithm cannot be used for signing.");
        }
    }
}
