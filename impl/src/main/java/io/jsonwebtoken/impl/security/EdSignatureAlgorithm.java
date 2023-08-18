/*
 * Copyright © 2023 jsonwebtoken.io
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
package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.KeyPairBuilder;
import io.jsonwebtoken.security.Request;
import io.jsonwebtoken.security.SecureRequest;
import io.jsonwebtoken.security.UnsupportedKeyException;
import io.jsonwebtoken.security.VerifyDigestRequest;

import java.security.Key;
import java.security.PrivateKey;

final class EdSignatureAlgorithm extends AbstractSignatureAlgorithm {

    private static final String ID = "EdDSA";

    private final EdwardsCurve preferredCurve;

    static final EdSignatureAlgorithm INSTANCE = new EdSignatureAlgorithm();

    static boolean isSigningKey(PrivateKey key) {
        EdwardsCurve curve = EdwardsCurve.findByKey(key);
        return curve != null && curve.isSignatureCurve();
    }

    private EdSignatureAlgorithm() {
        super(ID, ID);
        this.preferredCurve = EdwardsCurve.Ed448;
        Assert.isTrue(this.preferredCurve.isSignatureCurve(), "Must be signature curve, not key agreement curve.");
    }

    @Override
    protected String getJcaName(Request<?> request) {
        SecureRequest<?, ?> req = Assert.isInstanceOf(SecureRequest.class, request, "SecureRequests are required.");
        Key key = req.getKey();

        // If we're signing, and this instance's algorithm name is the default/generic 'EdDSA', then prefer the
        // signing key's curve algorithm ID.  This ensures the most specific JCA algorithm is used for signing,
        // (while generic 'EdDSA' is fine for validation)
        String jcaName = getJcaName(); //default for JCA interaction
        boolean signing = !(request instanceof VerifyDigestRequest);
        if (ID.equals(jcaName) && signing) { // see if we can get a more-specific curve algorithm identifier:
            EdwardsCurve curve = EdwardsCurve.findByKey(key);
            if (curve != null) {
                jcaName = curve.getJcaName(); // prefer the key's specific curve algorithm identifier during signing
            }
        }
        return jcaName;
    }

    @Override
    public KeyPairBuilder keyPair() {
        return this.preferredCurve.keyPair();
    }

    @Override
    protected void validateKey(Key key, boolean signing) {
        super.validateKey(key, signing);
        EdwardsCurve curve = EdwardsCurve.findByKey(key);
        if (curve != null && !curve.isSignatureCurve()) {
            String msg = curve.getId() + " keys may not be used with " + getId() + " digital signatures per " +
                    "https://www.rfc-editor.org/rfc/rfc8037.html#section-3.2";
            throw new UnsupportedKeyException(msg);
        }
    }
}
