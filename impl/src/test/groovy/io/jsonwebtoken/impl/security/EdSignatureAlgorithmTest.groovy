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
import io.jsonwebtoken.security.SignatureAlgorithm
import io.jsonwebtoken.security.SignatureException
import org.junit.Test

import java.security.PrivateKey
import java.security.PublicKey

import static org.junit.Assert.*

class EdSignatureAlgorithmTest {

    static List<EdSignatureAlgorithm> algs = [Jwts.SIG.EdDSA, Jwts.SIG.Ed25519, Jwts.SIG.Ed448] as List<EdSignatureAlgorithm>

    @Test
    void testJcaName() {
        assertEquals Jwts.SIG.EdDSA.getId(), Jwts.SIG.EdDSA.getJcaName()
        assertEquals EdwardsCurve.Ed25519.getId(), Jwts.SIG.Ed25519.getJcaName()
        assertEquals EdwardsCurve.Ed448.getId(), Jwts.SIG.Ed448.getJcaName()
    }

    @Test
    void testId() {
        //There is only one signature algorithm ID defined for Edwards curve keys per
        // https://www.rfc-editor.org/rfc/rfc8037#section-3.1 and
        // https://www.rfc-editor.org/rfc/rfc8037#section-5
        //
        // As such, the Ed25519 and Ed448 SignatureAlgorithm instances _must_ reflect the same ID since that's the
        // only one recognized by the spec.  They are effectively just aliases of EdDSA but have the added
        // functionality of generating Ed25519 and Ed448 keys, that's the only difference.
        for (EdSignatureAlgorithm alg : algs) {
            assertEquals Jwts.SIG.EdDSA.getId(), alg.getId() // all aliases of EdDSA per the RFC spec
        }
    }

    @Test
    void testKeyPairBuilder() {
        algs.each {
            def pair = it.keyPairBuilder().build()
            assertNotNull pair.public
            assertTrue pair.public instanceof PublicKey
            String alg = pair.public.getAlgorithm()
            assertTrue Jwts.SIG.EdDSA.getId().equals(alg) || alg.equals(it.preferredCurve.getId())

            alg = pair.private.getAlgorithm()
            assertTrue Jwts.SIG.EdDSA.getId().equals(alg) || alg.equals(it.preferredCurve.getId())
        }
    }

    /**
     * Likely when keys are from an HSM or PKCS key store
     */
    @Test
    void testGetAlgorithmJcaNameWhenCantFindCurve() {
        def key = new TestKey(algorithm: 'foo')
        algs.each {
            def payload = [0x00] as byte[]
            def req = new DefaultSecureRequest(payload, null , null, key)
            assertEquals it.getJcaName(), it.getJcaName(req)
        }
    }

    @Test
    void testEd25519SigVerifyWithEd448() {
        testIncorrectVerificationKey(Jwts.SIG.Ed25519, TestKeys.Ed25519.pair.private, TestKeys.Ed448.pair.public)
    }

    @Test
    void testEd25519SigVerifyWithX25519() {
        testInvalidVerificationKey(Jwts.SIG.Ed25519, TestKeys.Ed25519.pair.private, TestKeys.X25519.pair.public)
    }

    @Test
    void testEd25519SigVerifyWithX448() {
        testInvalidVerificationKey(Jwts.SIG.Ed25519, TestKeys.Ed25519.pair.private, TestKeys.X448.pair.public)
    }

    @Test
    void testEd448SigVerifyWithEd25519() {
        testIncorrectVerificationKey(Jwts.SIG.Ed448, TestKeys.Ed448.pair.private, TestKeys.Ed25519.pair.public)
    }

    @Test
    void testEd448SigVerifyWithX25519() {
        testInvalidVerificationKey(Jwts.SIG.Ed448, TestKeys.Ed448.pair.private, TestKeys.X25519.pair.public)
    }

    @Test
    void testEd448SigVerifyWithX448() {
        testInvalidVerificationKey(Jwts.SIG.Ed448, TestKeys.Ed448.pair.private, TestKeys.X448.pair.public)
    }

    static void testIncorrectVerificationKey(SignatureAlgorithm alg, PrivateKey priv, PublicKey pub) {
        try {
            testSig(alg, priv, pub)
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

    static void testInvalidVerificationKey(SignatureAlgorithm alg, PrivateKey priv, PublicKey pub) {
        try {
            testSig(alg, priv, pub)
            fail()
        } catch (UnsupportedJwtException expected) {
            def cause = expected.getCause()
            def keyCurve = EdwardsCurve.forKey(pub)
            String expectedMsg = "${keyCurve.getId()} keys may not be used with EdDSA digital signatures per https://www.rfc-editor.org/rfc/rfc8037#section-3.2"
            assertEquals expectedMsg, cause.getMessage()
        }
    }

    static void testSig(SignatureAlgorithm alg, PrivateKey signing, PublicKey verification) {
        String jwt = Jwts.builder().setIssuer('me').setAudience('you').signWith(signing, alg).compact()
        def token = Jwts.parser().verifyWith(verification).build().parseClaimsJws(jwt)
        assertEquals([alg: alg.getId()], token.header)
        assertEquals 'me', token.getPayload().getIssuer()
        assertEquals 'you', token.getPayload().getAudience()
    }
}
