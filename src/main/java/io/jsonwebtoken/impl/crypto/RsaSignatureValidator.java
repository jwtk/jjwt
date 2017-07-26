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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

public class RsaSignatureValidator extends RsaProvider implements SignatureValidator {

    private final Collection<SignerAndKey> SIGNERS;

    public static final class SignerAndKey {

        private final RsaSigner signer;
        private final Key key;

        public SignerAndKey(final RsaSigner signer, final Key key) {
            this.signer = signer;
            this.key = key;
        }
    }

    public RsaSignatureValidator(SignatureAlgorithm alg, Collection<Key> keys) {
        super(alg, null);

        Collection<SignerAndKey> SIGNERS = new ArrayList<SignerAndKey>();
        for (Key key: keys) {
            Assert.isTrue(key instanceof RSAPrivateKey || key instanceof RSAPublicKey,
                          "RSA Signature validation requires either a RSAPublicKey or RSAPrivateKey instance.");
            SIGNERS.add(new SignerAndKey(new RsaSigner(alg, key), key));
        }
        this.SIGNERS = SIGNERS;
    }

    @Override
    public boolean isValid(byte[] data, byte[] signature) {
        for (SignerAndKey signerAndKey: this.SIGNERS) {
            if (signerAndKey.key instanceof PublicKey) {
                Signature sig = createSignatureInstance();
                PublicKey publicKey = (PublicKey) signerAndKey.key;
                try {
                    if (doVerify(sig, publicKey, data, signature))
                        return true;
                } catch (Exception e) {
                    String msg = "Unable to verify RSA signature using configured PublicKey. " + e.getMessage();
                    throw new SignatureException(msg, e);
                }
            } else {
                Assert.notNull(this.SIGNERS, "RSA Signer instance cannot be null.  This is a bug.  Please report it.");
                byte[] computed = signerAndKey.signer.sign(data);
                if (Arrays.equals(computed, signature))
                    return true;
            }
        }
        return false;
    }

    protected boolean doVerify(Signature sig, PublicKey publicKey, byte[] data, byte[] signature)
        throws InvalidKeyException, java.security.SignatureException {
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }

}
