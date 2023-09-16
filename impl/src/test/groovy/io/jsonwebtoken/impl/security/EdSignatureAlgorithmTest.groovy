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
package io.jsonwebtoken.impl.security

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.UnsupportedJwtException
import io.jsonwebtoken.security.SignatureException
import org.junit.Test

import java.security.PrivateKey
import java.security.PublicKey

import static org.junit.Assert.*

class EdSignatureAlgorithmTest {

    static EdSignatureAlgorithm alg = Jwts.SIG.EdDSA as EdSignatureAlgorithm

    @Test
    void testJcaName() {
        // the JWT RFC id and the JDK standard name appen to be the same:
        assertEquals alg.getId(), alg.getJcaName()
    }

    @Test
    void testId() {
        // https://www.rfc-editor.org/rfc/rfc8037#section-3.1:
        assertEquals 'EdDSA', alg.getId()
    }

    @Test
    void testKeyPairBuilder() {
        def pair = alg.keyPair().build()
        assertNotNull pair.public
        assertTrue pair.public instanceof PublicKey
        String algName = pair.public.getAlgorithm()
        assertTrue alg.getId().equals(algName) || algName.equals(alg.preferredCurve.getId())

        algName = pair.private.getAlgorithm()
        assertTrue alg.getId().equals(algName) || algName.equals(alg.preferredCurve.getId())
    }

    /**
     * Likely when keys are from an HSM or PKCS key store
     */
    @Test
    void testGetRequestJcaNameByKeyAlgorithmNameOnly() {
        def key = new TestKey(algorithm: EdwardsCurve.X25519.OID)
        def payload = [0x00] as byte[]
        def req = new DefaultSecureRequest(payload, null, null, key)
        assertEquals 'X25519', alg.getJcaName(req) // Not the EdDSA default
    }

    @Test
    void testEd25519SigVerifyWithEd448() {
        testIncorrectVerificationKey(TestKeys.Ed25519.pair.private, TestKeys.Ed448.pair.public)
    }

    @Test
    void testEd25519SigVerifyWithX25519() {
        testInvalidVerificationKey(TestKeys.Ed25519.pair.private, TestKeys.X25519.pair.public)
    }

    @Test
    void testEd25519SigVerifyWithX448() {
        testInvalidVerificationKey(TestKeys.Ed25519.pair.private, TestKeys.X448.pair.public)
    }

    @Test
    void testEd448SigVerifyWithEd25519() {
        testIncorrectVerificationKey(TestKeys.Ed448.pair.private, TestKeys.Ed25519.pair.public)
    }

    @Test
    void testEd448SigVerifyWithX25519() {
        testInvalidVerificationKey(TestKeys.Ed448.pair.private, TestKeys.X25519.pair.public)
    }

    @Test
    void testEd448SigVerifyWithX448() {
        testInvalidVerificationKey(TestKeys.Ed448.pair.private, TestKeys.X448.pair.public)
    }

    static void testIncorrectVerificationKey(PrivateKey priv, PublicKey pub) {
        try {
            testSig(priv, pub)
            fail()
        } catch (SignatureException expected) {
            // SignatureException message can differ depending on JDK version and if BC is enabled or not:
            // BC Provider signature.verify() will just return false, but SunEC provider signature.verify() throws an
            // exception with its own message.  As a result, we should always get a SignatureException, but we need
            // to check the message for either scenario depending on the JVM version running the tests:
            String exMsg = expected.getMessage()
            String expectedMsg = 'JWT signature does not match locally computed signature. JWT validity cannot be asserted and should not be trusted.'
            String expectedMsg2 = "Unable to verify EdDSA signature with JCA algorithm 'EdDSA' using key {${pub}}: ${expected.getCause()?.getMessage()}"
            assertTrue exMsg.equals(expectedMsg) || exMsg.equals(expectedMsg2)
        }
    }

    static void testInvalidVerificationKey(PrivateKey priv, PublicKey pub) {
        try {
            testSig(priv, pub)
            fail()
        } catch (UnsupportedJwtException expected) {
            def cause = expected.getCause()
            def keyCurve = EdwardsCurve.forKey(pub)
            String expectedMsg = "${keyCurve.getId()} keys may not be used with EdDSA digital signatures per " +
                    "https://www.rfc-editor.org/rfc/rfc8037.html#section-3.2"
            assertEquals expectedMsg, cause.getMessage()
        }
    }

    static void testSig(PrivateKey signing, PublicKey verification) {
        String jwt = Jwts.builder().issuer('me').audience('you').signWith(signing, alg).compact()
        def token = Jwts.parser().verifyWith(verification).build().parseClaimsJws(jwt)
        assertEquals([alg: alg.getId()], token.header)
        assertEquals 'me', token.getPayload().getIssuer()
        assertEquals 'you', token.getPayload().getAudience().iterator().next()
    }
}
