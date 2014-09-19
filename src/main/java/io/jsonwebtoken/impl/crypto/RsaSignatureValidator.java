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

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;

public class RsaSignatureValidator extends RsaProvider implements SignatureValidator {

    public RsaSignatureValidator(SignatureAlgorithm alg, Key key) {
        super(alg, key);
        Assert.isTrue(key instanceof PrivateKey || key instanceof PublicKey,
                      "RSA Signature validation requires either a PublicKey or PrivateKey instance.");
    }

    @Override
    public boolean isValid(byte[] data, byte[] signature) {

        if (key instanceof PublicKey) {
            Signature sig = createSignatureInstance();
            PublicKey publicKey = (PublicKey) key;
            try {
                sig.initVerify(publicKey);
                sig.update(data);
                return sig.verify(signature);
            } catch (Exception e) {
                String msg = "Unable to verify RSA signature using configured PublicKey.  " + e.getMessage();
                throw new SignatureException(msg, e);
            }
        } else {
            byte[] computed = new RsaSigner(alg, key).sign(data);
            return Arrays.equals(computed, signature);
        }
    }

}
