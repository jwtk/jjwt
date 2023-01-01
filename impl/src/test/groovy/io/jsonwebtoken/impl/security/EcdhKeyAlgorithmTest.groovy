/*
 * Copyright (C) 2021 jsonwebtoken.io
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
package io.jsonwebtoken.impl.security

import io.jsonwebtoken.MalformedJwtException
import io.jsonwebtoken.impl.DefaultJweHeader
import io.jsonwebtoken.security.DecryptionKeyRequest
import io.jsonwebtoken.security.EncryptionAlgorithms
import io.jsonwebtoken.security.InvalidKeyException
import io.jsonwebtoken.security.Jwks
import org.junit.Test

import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey

import static org.junit.Assert.assertEquals
import static org.junit.Assert.fail

/**
 * The {@link EcdhKeyAlgorithm} class is mostly tested already in RFC Appendix tests, so this class
 * adds in tests for assertions/conditionals that aren't as easily tested elsewhere.
 */
class EcdhKeyAlgorithmTest {

    @Test
    void testDecryptionWithMissingEcPublicJwk() {

        def alg = new EcdhKeyAlgorithm()
        ECPrivateKey decryptionKey = TestKeys.ES256.pair.private as ECPrivateKey

        def header = new DefaultJweHeader()

        DecryptionKeyRequest req = new DefaultDecryptionKeyRequest('test'.getBytes(), null, null, header, EncryptionAlgorithms.A128GCM, decryptionKey)

        try {
            alg.getDecryptionKey(req)
            fail()
        } catch (MalformedJwtException expected) {
            String msg = "JWE header is missing required 'epk' (Ephemeral Public Key) value."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testDecryptionWithEcPublicJwkOnInvalidCurve() {

        def alg = new EcdhKeyAlgorithm()
        ECPrivateKey decryptionKey = TestKeys.ES256.pair.private as ECPrivateKey // Expected curve for this is P-256

        def header = new DefaultJweHeader()
        // This uses curve P-384 instead, does not match private key, so it's unexpected:
        def jwk = Jwks.builder().forKey(TestKeys.ES384.pair.public as ECPublicKey).build()
        header.put('epk', jwk)

        DecryptionKeyRequest req = new DefaultDecryptionKeyRequest('test'.getBytes(), null, null, header, EncryptionAlgorithms.A128GCM, decryptionKey)

        try {
            alg.getDecryptionKey(req)
            fail()
        } catch (InvalidKeyException expected) {
            assertEquals("JWE Header 'epk' (Ephemeral Public Key) value does not represent a point on the expected curve.", expected.getMessage())
        }
    }
}
