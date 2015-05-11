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
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

public class RsaSignatureValidator extends RsaProvider implements SignatureValidator {

    private final RsaSigner SIGNER;

    public RsaSignatureValidator(SignatureAlgorithm alg, Key key) {
        super(alg, key);
        Assert.isTrue(key instanceof RSAPrivateKey || key instanceof RSAPublicKey,
                      "RSA Signature validation requires either a RSAPublicKey or RSAPrivateKey instance.");
        this.SIGNER = key instanceof RSAPrivateKey ? new RsaSigner(alg, key) : null;
    }

    @Override
    public boolean isValid(byte[] data, byte[] signature) {
        if (key instanceof PublicKey) {
            Signature sig = createSignatureInstance();
            PublicKey publicKey = (PublicKey) key;
            try {
                return doVerify(sig, publicKey, data, signature);
            } catch (Exception e) {
                String msg = "Unable to verify RSA signature using configured PublicKey. " + e.getMessage();
                throw new SignatureException(msg, e);
            }
        } else {
            Assert.notNull(this.SIGNER, "RSA Signer instance cannot be null.  This is a bug.  Please report it.");
            byte[] computed = this.SIGNER.sign(data);
            return Arrays.equals(computed, signature);
        }
    }

    protected boolean doVerify(Signature sig, PublicKey publicKey, byte[] data, byte[] signature)
        throws InvalidKeyException, java.security.SignatureException {
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }

}
