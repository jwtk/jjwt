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
package io.jsonwebtoken.impl.crypto

import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.SignatureException
import org.testng.annotations.Test

import java.security.InvalidKeyException
import java.security.PublicKey
import java.security.Signature

import static org.testng.Assert.*

class EllipticCurveSignatureValidatorTest {

    @Test
    void testDoVerifyWithInvalidKeyException() {

        String msg = 'foo'
        final InvalidKeyException ex = new InvalidKeyException(msg)

        def v = new EllipticCurveSignatureValidator(SignatureAlgorithm.ES512, EllipticCurveProvider.generateKeyPair().public) {
            @Override
            protected boolean doVerify(Signature sig, PublicKey pk, byte[] data, byte[] signature) throws InvalidKeyException, java.security.SignatureException {
                throw ex;
            }
        }

        byte[] bytes = new byte[16]
        byte[] signature = new byte[16]
        SignatureProvider.DEFAULT_SECURE_RANDOM.nextBytes(bytes)
        SignatureProvider.DEFAULT_SECURE_RANDOM.nextBytes(signature)

        try {
            v.isValid(bytes, signature)
            fail();
        } catch (SignatureException se) {
            assertEquals se.message, 'Unable to verify Elliptic Curve signature using configured ECPublicKey. ' + msg
            assertSame se.cause, ex
        }
    }
}
