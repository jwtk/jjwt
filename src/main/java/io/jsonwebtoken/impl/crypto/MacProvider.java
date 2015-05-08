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

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Signature;

public abstract class MacProvider extends SignatureProvider {

    protected MacProvider(SignatureAlgorithm alg, Key key) {
        super(alg, key);
        Assert.isTrue(alg.isHmac(), "SignatureAlgorithm must be a HMAC SHA algorithm.");
    }

    public static SecretKey generateKey() {
        return generateKey(SignatureAlgorithm.HS512);
    }

    public static SecretKey generateKey(SignatureAlgorithm alg) {
        return generateKey(alg, SignatureProvider.DEFAULT_SECURE_RANDOM);
    }

    public static SecretKey generateKey(SignatureAlgorithm alg, SecureRandom random) {

        Assert.isTrue(alg.isHmac(), "SignatureAlgorithm argument must represent an HMAC algorithm.");

        byte[] bytes;

        switch(alg) {
            case HS256:
                bytes = new byte[32];
                break;
            case HS384:
                bytes = new byte[48];
                break;
            default:
                bytes = new byte[64];
        }

        random.nextBytes(bytes);

        return new SecretKeySpec(bytes, alg.getJcaName());
    }
}
