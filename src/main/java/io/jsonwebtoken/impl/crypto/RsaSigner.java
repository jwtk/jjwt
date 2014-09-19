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
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.lang.Assert;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.Signature;

public class RsaSigner extends RsaProvider implements Signer {

    public RsaSigner(SignatureAlgorithm alg, Key key) {
        super(alg, key);
        Assert.isInstanceOf(PrivateKey.class, key, "RSA signatures be computed using a PrivateKey.");
    }

    @Override
    public byte[] sign(byte[] data) {
        try {
            return doSign(data);
        } catch (InvalidKeyException e) {
            throw new SignatureException("Invalid RSA PrivateKey. " + e.getMessage(), e);
        } catch (java.security.SignatureException e) {
            throw new SignatureException("Unable to calculate signature using RSA PrivateKey. " + e.getMessage(), e);
        }
    }

    protected byte[] doSign(byte[] data) throws InvalidKeyException, java.security.SignatureException {
        Assert.isInstanceOf(PrivateKey.class, key, "RSA signatures be computed using a PrivateKey.");
        PrivateKey privateKey = (PrivateKey)key;
        Signature sig = createSignatureInstance();
        sig.initSign(privateKey);
        sig.update(data);
        return sig.sign();
    }

}
