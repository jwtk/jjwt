/*
 * Copyright (C) 2015 jsonwebtoken.io
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

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.util.Collection;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.lang.Assert;

public class EllipticCurveSignatureValidator extends EllipticCurveProvider implements SignatureValidator {

    private static final String EC_PUBLIC_KEY_REQD_MSG =
        "Elliptic Curve signature validation requires an ECPublicKey instance.";

    private final Collection<Key> keys;

    public EllipticCurveSignatureValidator(SignatureAlgorithm alg, Collection<Key> keys) {
        super(alg, null);
        this.keys = keys;
        for (Key key: keys)
            Assert.isTrue(key instanceof ECPublicKey, EC_PUBLIC_KEY_REQD_MSG);
    }

    @Override
    public boolean isValid(byte[] data, byte[] signature) {
        Signature sig = createSignatureInstance();
        for (Key key: this.keys) {
            PublicKey publicKey = (PublicKey) key;
            try {
                int expectedSize = getSignatureByteArrayLength(this.alg);
                /**
                 *
                 * If the expected size is not valid for JOSE, fall back to ASN.1 DER signature.
                 * This fallback is for backwards compatibility ONLY (to support tokens generated by previous versions of jjwt)
                 * and backwards compatibility will possibly be removed in a future version of this library.
                 *
                 * **/
                byte[] derSignature = expectedSize != signature.length && signature[0] == 0x30 ? signature : EllipticCurveProvider.transcodeSignatureToDER(signature);
                if (doVerify(sig, publicKey, data, derSignature))
                    return true;
            } catch (Exception e) {
                String msg = "Unable to verify Elliptic Curve signature using configured ECPublicKey. " + e.getMessage();
                throw new SignatureException(msg, e);
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
