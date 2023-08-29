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

import io.jsonwebtoken.JweHeader
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.MalformedJwtException
import io.jsonwebtoken.impl.DefaultJweHeader
import io.jsonwebtoken.impl.DefaultMutableJweHeader
import io.jsonwebtoken.security.DecryptionKeyRequest
import io.jsonwebtoken.security.InvalidKeyException
import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.UnsupportedKeyException
import org.junit.Test

import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

import static org.junit.Assert.*

/**
 * The {@link EcdhKeyAlgorithm} class is mostly tested already in RFC Appendix tests, so this class
 * adds in tests for assertions/conditionals that aren't as easily tested elsewhere.
 */
class EcdhKeyAlgorithmTest {

    @Test
    void testEdwardsEncryptionWithRequestProvider() {
        def alg = new EcdhKeyAlgorithm()
        PublicKey encKey = TestKeys.X25519.pair.public as PublicKey
        def header = new DefaultMutableJweHeader(Jwts.header())
        def provider = TestKeys.BC
        def request = new DefaultKeyRequest(encKey, provider, null, header, Jwts.ENC.A128GCM)
        def result = alg.getEncryptionKey(request)
        assertNotNull result.getKey()
    }

    @Test
    void testEdwardsDecryptionWithRequestProvider() {
        def alg = new EcdhKeyAlgorithm()
        def enc = Jwts.ENC.A128GCM
        PublicKey encKey = TestKeys.X25519.pair.public as PublicKey
        PrivateKey decKey = TestKeys.X25519.pair.private as PrivateKey
        def header = Jwts.header()
        def provider = TestKeys.BC

        // encrypt
        def delegate = new DefaultMutableJweHeader(header)
        def request = new DefaultKeyRequest(encKey, provider, null, delegate, enc)
        def result = alg.getEncryptionKey(request)
        def cek = result.getKey()
        def cekCiphertext = result.getPayload()

        JweHeader jweHeader = header.build() as JweHeader

        def decRequest = new DefaultDecryptionKeyRequest(cekCiphertext, provider, null, jweHeader, enc, decKey)
        def resultCek = alg.getDecryptionKey(decRequest)
        assertEquals(cek, resultCek)
    }

    @Test
    void testDecryptionWithMissingEcPublicJwk() {

        def alg = new EcdhKeyAlgorithm()
        ECPrivateKey decryptionKey = TestKeys.ES256.pair.private as ECPrivateKey

        def header = new DefaultJweHeader([:])

        DecryptionKeyRequest req = new DefaultDecryptionKeyRequest('test'.getBytes(), null, null, header, Jwts.ENC.A128GCM, decryptionKey)

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

        // This uses curve P-384 instead, does not match private key, so it's unexpected:
        def jwk = Jwks.builder().key(TestKeys.ES384.pair.public as ECPublicKey).build()
        JweHeader header = Jwts.header().add('epk', jwk).build() as JweHeader

        DecryptionKeyRequest req = new DefaultDecryptionKeyRequest('test'.getBytes(), null, null, header, Jwts.ENC.A128GCM, decryptionKey)

        try {
            alg.getDecryptionKey(req)
            fail()
        } catch (InvalidKeyException expected) {
            assertEquals("JWE Header 'epk' (Ephemeral Public Key) value does not represent a point on the expected curve.", expected.getMessage())
        }
    }


    @Test
    void testEncryptionWithInvalidPublicKey() {
        def alg = new EcdhKeyAlgorithm()
        PublicKey encKey = TestKeys.RS256.pair.public as PublicKey // not an elliptic curve key, must fail
        def header = new DefaultMutableJweHeader(Jwts.header())
        def request = new DefaultKeyRequest(encKey, null, null, header, Jwts.ENC.A128GCM)
        try {
            alg.getEncryptionKey(request)
            fail()
        } catch (UnsupportedKeyException expected) {
            String msg = 'Key Encryption Key must be a java.security.interfaces.ECKey or Edwards Curve ' +
                    'PublicKey on a supported curve. Cause: sun.security.rsa.RSAPublicKeyImpl with ' +
                    'algorithm \'RSA\' is not a recognized Edwards Curve key.'
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testDecryptionWithInvalidPrivateKey() {
        def alg = new EcdhKeyAlgorithm()
        PrivateKey key = TestKeys.RS256.pair.private as PrivateKey // not an elliptic curve key, must fail
        def jwk = Jwks.builder().key(TestKeys.RS256.pair.public as RSAPublicKey).build()
        JweHeader header = Jwts.header().add('epk', jwk).build() as JweHeader
        def request = new DefaultDecryptionKeyRequest('test'.getBytes(), null, null, header, Jwts.ENC.A128GCM, key)
        try {
            alg.getDecryptionKey(request)
            fail()
        } catch (UnsupportedKeyException expected) {
            String msg = 'Key Decryption Key must be a java.security.interfaces.ECKey or Edwards Curve ' +
                    'PrivateKey on a supported curve. Cause: sun.security.rsa.RSAPrivateCrtKeyImpl with ' +
                    'algorithm \'RSA\' is not a recognized Edwards Curve key.'
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testDecryptionWithoutEpk() {
        def alg = new EcdhKeyAlgorithm()
        PrivateKey key = TestKeys.ES256.pair.private as PrivateKey // valid key
        def header = new DefaultJweHeader([:]) // no 'epk' value
        def request = new DefaultDecryptionKeyRequest('test'.getBytes(), null, null, header, Jwts.ENC.A128GCM, key)
        try {
            alg.getDecryptionKey(request)
            fail()
        } catch (MalformedJwtException expected) {
            String msg = 'JWE header is missing required \'epk\' (Ephemeral Public Key) value.'
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testECDecryptionWithNonECEpk() {
        def alg = new EcdhKeyAlgorithm()
        PrivateKey key = TestKeys.ES256.pair.private as PrivateKey // valid key
        def jwk = Jwks.builder().key(TestKeys.RS256.pair.public as RSAPublicKey).build() // invalid epk
        JweHeader header = Jwts.header().add('epk', jwk).build() as JweHeader
        def request = new DefaultDecryptionKeyRequest('test'.getBytes(), null, null, header, Jwts.ENC.A128GCM, key)
        try {
            alg.getDecryptionKey(request)
            fail()
        } catch (UnsupportedKeyException expected) {
            String msg = 'JWE Header \'epk\' (Ephemeral Public Key) value is not a supported Elliptic Curve Public ' +
                    'JWK. Value: {kty=RSA, n=vPYf1VSy58i6ic93goenzF5UO9oLxyiTSF64lGFUJ6_MBDydAvY9PS76ymvhUcSrsDUHgb' +
                    '0arsp6MDXOfZxYHn2C7o39n8-bQ7yS4hQm6kkl8KB5OiOkJFkFjEHrwnqykXygx1VFpcVpbBvxDn640ODEScWyoUUPd4sO' +
                    'K-esTt4D9-q0PXsXzfRT4eOrnpXHJTan_KK_a-UYmfWPr-xIEPUxnLPCD68mIHoSPAaJiv37SkAWHJ9-fm_DfnYTwTi0rx' +
                    'e2FRQ1-vkOxe6C2-n1ebsqCZPKr0J_2MfwqP0raxLfyGicxM5ee5RSTTRMCA4UyX5dubZvh2pLoaS8PCZajw, e=AQAB}'
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testEdwardsDecryptionWithNonEdwardsEpk() {
        def alg = new EcdhKeyAlgorithm()
        PrivateKey key = TestKeys.X25519.pair.private as PrivateKey // valid key
        def jwk = Jwks.builder().key(TestKeys.RS256.pair.public as RSAPublicKey).build() // invalid epk
        JweHeader header = Jwts.header().add('epk', jwk).build() as JweHeader
        def request = new DefaultDecryptionKeyRequest('test'.getBytes(), null, null, header, Jwts.ENC.A128GCM, key)
        try {
            alg.getDecryptionKey(request)
            fail()
        } catch (UnsupportedKeyException expected) {
            String msg = 'JWE Header \'epk\' (Ephemeral Public Key) value is not a supported Elliptic Curve Public ' +
                    'JWK. Value: {kty=RSA, n=vPYf1VSy58i6ic93goenzF5UO9oLxyiTSF64lGFUJ6_MBDydAvY9PS76ymvhUcSrsDUHgb' +
                    '0arsp6MDXOfZxYHn2C7o39n8-bQ7yS4hQm6kkl8KB5OiOkJFkFjEHrwnqykXygx1VFpcVpbBvxDn640ODEScWyoUUPd4sO' +
                    'K-esTt4D9-q0PXsXzfRT4eOrnpXHJTan_KK_a-UYmfWPr-xIEPUxnLPCD68mIHoSPAaJiv37SkAWHJ9-fm_DfnYTwTi0rx' +
                    'e2FRQ1-vkOxe6C2-n1ebsqCZPKr0J_2MfwqP0raxLfyGicxM5ee5RSTTRMCA4UyX5dubZvh2pLoaS8PCZajw, e=AQAB}'
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testEdwardsDecryptionWithEpkOnDifferentCurve() {
        def alg = new EcdhKeyAlgorithm()
        PrivateKey key = TestKeys.X25519.pair.private as PrivateKey // valid key
        def jwk = Jwks.builder().key(TestKeys.X448.pair.public as PublicKey).build() // epk is not on X25519
        JweHeader header = Jwts.header().add('epk', jwk).build() as JweHeader
        def request = new DefaultDecryptionKeyRequest('test'.getBytes(), null, null, header, Jwts.ENC.A128GCM, key)
        try {
            alg.getDecryptionKey(request)
            fail()
        } catch (InvalidKeyException expected) {
            String msg = 'JWE Header \'epk\' (Ephemeral Public Key) value does not represent a point on the ' +
                    'expected curve. Value: {kty=OKP, crv=X448, ' +
                    'x=XxQlWa22S36qjui_M2IBT5vg0CmmLJkpBhXeiuBptUxJ_nnD0uITBH5N9PHkhOM8gfGtNkh6Jwc}'
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testAssertEcCurveFails() {
        def key = TestKeys.HS256
        try {
            EcdhKeyAlgorithm.assertEcCurve(key, 'foo.')
            fail()
        } catch (UnsupportedKeyException expected) {
            String msg = "foo. Cause: Unable to determine JWA-standard Elliptic Curve for specified " +
                    "key: ${KeysBridge.toString(key)}"
            assertEquals msg, expected.getMessage()
        }
    }
}
