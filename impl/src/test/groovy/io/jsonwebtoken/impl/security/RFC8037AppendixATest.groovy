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
import io.jsonwebtoken.impl.RfcTests
import io.jsonwebtoken.security.Curve
import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.OctetPrivateJwk
import io.jsonwebtoken.security.OctetPublicJwk
import org.junit.Test

import java.nio.charset.StandardCharsets
import java.security.*

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertTrue

class RFC8037AppendixATest {

    // https://www.rfc-editor.org/rfc/rfc8037#appendix-A.1 :
    static final String A1_ED25519_PRIVATE_JWK_STRING = RfcTests.stripws('''
    {
      "kty":"OKP",
      "crv":"Ed25519",
      "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
      "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    }''')

    // https://www.rfc-editor.org/rfc/rfc8037#appendix-A.2
    static final String A2_ED25519_PUBLIC_JWK_STRING = RfcTests.stripws('''
    {
      "kty":"OKP","crv":"Ed25519",
      "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    }''')

    // https://www.rfc-editor.org/rfc/rfc8037#appendix-A.3
    static final A3_JWK_THUMBPRINT_B64URL = 'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k'
    static final A3_JWK_THUMMBPRINT_HEX = '90facafea9b1556698540f70c0117a22ea37bd5cf3ed3c47093c1707282b4b89'

    static final A4_JWS_PAYLOAD = 'Example of Ed25519 signing'

    static final String A4_JWS_COMPACT = RfcTests.stripws('''
    eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCj
    P0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_Mu
    M0KAg''')

    static OctetPrivateJwk a1Jwk() {
        Jwks.parser().build().parse(A1_ED25519_PRIVATE_JWK_STRING) as OctetPrivateJwk
    }

    static OctetPublicJwk a2Jwk() {
        Jwks.parser().build().parse(A2_ED25519_PUBLIC_JWK_STRING) as OctetPublicJwk
    }


    @Test
    void testSections_A1_A2_and_A3() {
        def privJwk = a1Jwk()
        assertTrue privJwk instanceof OctetPrivateJwk
        PrivateKey privKey = privJwk.toKey() as PrivateKey
        PublicKey pubKey = privJwk.toPublicJwk().toKey() as PublicKey

        def builtPrivJwk = Jwks.builder().key(privKey).publicKey(pubKey).build()

        //output should equal RFC input:
        assertEquals privJwk, builtPrivJwk

        // Our built public JWK must reflect the RFC public JWK string value:
        def a2PubJwk = a2Jwk()
        assertTrue a2PubJwk instanceof OctetPublicJwk
        PublicKey a2PubJwkKey = a2PubJwk.toKey() as PublicKey

        assertEquals a2PubJwk, privJwk.toPublicJwk()
        assertEquals a2PubJwkKey, pubKey

        // Assert Section A.3 values:
        def privThumbprint = privJwk.thumbprint()
        def pubThumbprint = a2PubJwk.thumbprint()
        assertEquals(privThumbprint, pubThumbprint)

        assertEquals A3_JWK_THUMBPRINT_B64URL, privThumbprint.toString()
        assertEquals A3_JWK_THUMBPRINT_B64URL, pubThumbprint.toString()

        assertEquals A3_JWK_THUMMBPRINT_HEX, privThumbprint.toByteArray().encodeHex().toString()
        assertEquals A3_JWK_THUMMBPRINT_HEX, pubThumbprint.toByteArray().encodeHex().toString()
    }

    @Test
    void test_Sections_A4_and_A5() {
        def privJwk = a1Jwk()
        String compact = Jwts.builder()
                .content(A4_JWS_PAYLOAD.getBytes(StandardCharsets.UTF_8))
                .signWith(privJwk.toKey() as PrivateKey, Jwts.SIG.EdDSA)
                .compact()
        assertEquals A4_JWS_COMPACT, compact

        def pubJwk = a2Jwk()
        def payloadBytes = Jwts.parser().verifyWith(pubJwk.toKey()).build().parse(compact).getPayload() as byte[]
        def payload = new String(payloadBytes, StandardCharsets.UTF_8)
        assertEquals A4_JWS_PAYLOAD, payload
    }


    /**
     * https://www.rfc-editor.org/rfc/rfc8037#appendix-A indicates the public/private key pairs used for test
     * vectors for sections A6 and A7 are defined in <a href="https://www.rfc-editor.org/rfc/rfc7748">RFC 7748</a>.
     * Diffie-Hellman curve 25519 (X25519) test vectors are in
     * <a href="https://www.rfc-editor.org/rfc/rfc7748#section-6.1">RFC 7748, Section 6.1</a> specifically.
     */
    @Test
    void testSectionA6() { // defined in https://www.rfc-editor.org/rfc/rfc8037#appendix-A.6

        // These two values are defined in https://www.rfc-editor.org/rfc/rfc7748#section-6.1:
        def bobPubKeyHex = 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f'
        def bobPrivKeyHex = '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb'

        //convert these two values to a JWK for convenient reference:
        def bobPrivJwk = Jwks.builder().add([
                kty: "OKP", crv: "X25519", kid: "Bob",
                x  : bobPubKeyHex.decodeHex().encodeBase64Url() as String,
                d  : bobPrivKeyHex.decodeHex().encodeBase64Url() as String
        ]).build() as OctetPrivateJwk

        // RFC-specified test vectors to be used during DH calculation:
        def rfcEphemeralSecretHex = RfcTests.stripws('''
        77 07 6d 0a 73 18 a5 7d 3c 16 c1 72 51 b2 66 45
        df 4c 2f 87 eb c0 99 2a b1 77 fb a5 1d b9 2c 2a''')

        def rfcEphemeralPubKeyHex = RfcTests.stripws('''
        85 20 f0 09 89 30 a7 54 74 8b 7d dc b4 3e f7 5a
        0d bf 3a 0d 26 38 1a f4 eb a4 a9 8e aa 9b 4e 6a''')

        //Turn these two values into a Java KeyPair, and ensure it is used during key algorithm execution:
        final OctetPrivateJwk ephemJwk = Jwks.builder().add([
                kty: "OKP",
                crv: "X25519",
                x  : rfcEphemeralPubKeyHex.decodeHex().encodeBase64Url() as String,
                d  : rfcEphemeralSecretHex.decodeHex().encodeBase64Url() as String
        ]).build() as OctetPrivateJwk

        // ensure this is used during key algorithm execution per the RFC test case:
        def alg = new EcdhKeyAlgorithm(Jwts.KEY.A128KW) {
            @Override
            protected KeyPair generateKeyPair(Curve curve, Provider provider, SecureRandom random) {
                return ephemJwk.toKeyPair().toJavaKeyPair()
            }
        }

        // the RFC test vectors don't specify a JWE body/content, so we'll just add a random issuer claim and verify
        // that on decryption:
        final String issuer = RfcTests.srandom()

        // Create the test case JWE with the 'kid' header to ensure the output matches the RFC expected value:
        String jwe = Jwts.builder()
                .header().keyId(bobPrivJwk.getId()).and()
                .setIssuer(issuer)
                .encryptWith(bobPrivJwk.toPublicJwk().toKey() as PublicKey, alg, Jwts.ENC.A128GCM)
                .compact()

        // the constructed JWE should have the following protected header:
        String rfcExpectedProtectedHeaderJson = RfcTests.stripws('''
        {
          "alg": "ECDH-ES+A128KW",
          "epk": {
            "kty": "OKP",
            "crv": "X25519",
            "x": "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"
          },
          "enc": "A128GCM",
          "kid": "Bob"
        }''')

        String jweHeaderJson = new String(jwe.substring(0, jwe.indexOf('.')).decodeBase64Url(), StandardCharsets.UTF_8)

        // since JSON key/value ordering in JSON strings is not guaranteed, we change them to Maps and do equality
        // assertions that way:
        def rfcExpectedHeaderMap = RfcTests.jsonToMap(rfcExpectedProtectedHeaderJson)
        def jweHeaderMap = RfcTests.jsonToMap(jweHeaderJson)
        assertEquals(rfcExpectedHeaderMap, jweHeaderMap)
        assertEquals(rfcExpectedHeaderMap.get('epk'), jweHeaderMap.get('epk'))

        //ensure that bob can decrypt:
        def jwt = Jwts.parser().decryptWith(bobPrivJwk.toKey() as PrivateKey).build().parseClaimsJwe(jwe)

        assertEquals(issuer, jwt.getPayload().getIssuer())
    }

    /**
     * https://www.rfc-editor.org/rfc/rfc8037#appendix-A indicates the public/private key pairs used for test
     * vectors for sections A6 and A7 are defined in <a href="https://www.rfc-editor.org/rfc/rfc7748">RFC 7748</a>.
     * For Diffie-Hellman curve 448 (X448) test vectors are in
     * <a href="https://www.rfc-editor.org/rfc/rfc7748#section-6.2">RFC 7748, Section 6.2</a> specifically.
     */
    @Test
    void testSectionA7() { // defined in https://www.rfc-editor.org/rfc/rfc8037#appendix-A.7

        // These two values are defined in https://www.rfc-editor.org/rfc/rfc7748#section-6.2
        // (Appendex A.7 oddly refers to this key holder as "Dave" when their own referenced RFC test vectors
        // (RFC 7748, Section 6.2) calls this holder "Bob".  We'll keep the 'bob' variable name references, but change
        // the 'kid' value to "Dave" to match Section A.7 header values:
        def bobPubKeyHex = '3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609'
        def bobPrivKeyHex = '1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d'

        //convert these two values to a JWK for convenient reference:
        def bobPrivJwk = Jwks.builder().add([
                kty: "OKP", crv: "X448", kid: "Dave", // "Dave" instead of expected "Bob"
                x  : bobPubKeyHex.decodeHex().encodeBase64Url() as String,
                d  : bobPrivKeyHex.decodeHex().encodeBase64Url() as String
        ]).build() as OctetPrivateJwk

        // RFC-specified test vectors to be used during DH calculation:
        def rfcEphemeralSecretHex = RfcTests.stripws('''
        9a 8f 49 25 d1 51 9f 57 75 cf 46 b0 4b 58 00 d4
        ee 9e e8 ba e8 bc 55 65 d4 98 c2 8d d9 c9 ba f5
        74 a9 41 97 44 89 73 91 00 63 82 a6 f1 27 ab 1d
        9a c2 d8 c0 a5 98 72 6b''')

        def rfcEphemeralPubKeyHex = RfcTests.stripws('''
        9b 08 f7 cc 31 b7 e3 e6 7d 22 d5 ae a1 21 07 4a
        27 3b d2 b8 3d e0 9c 63 fa a7 3d 2c 22 c5 d9 bb
        c8 36 64 72 41 d9 53 d4 0c 5b 12 da 88 12 0d 53
        17 7f 80 e5 32 c4 1f a0''')

        //Turn these two values into a Java KeyPair, and ensure it is used during key algorithm execution:
        final OctetPrivateJwk ephemJwk = Jwks.builder().add([
                kty: "OKP",
                crv: "X448",
                x  : rfcEphemeralPubKeyHex.decodeHex().encodeBase64Url() as String,
                d  : rfcEphemeralSecretHex.decodeHex().encodeBase64Url() as String
        ]).build() as OctetPrivateJwk

        // ensure this is used during key algorithm execution per the RFC test case:
        def alg = new EcdhKeyAlgorithm(Jwts.KEY.A256KW) {
            @Override
            protected KeyPair generateKeyPair(Curve curve, Provider provider, SecureRandom random) {
                return ephemJwk.toKeyPair().toJavaKeyPair()
            }
        }

        // the RFC test vectors don't specify a JWE body/content, so we'll just add a random issuer claim and verify
        // that on decryption:
        final String issuer = RfcTests.srandom()

        // Create the test case JWE with the 'kid' header to ensure the output matches the RFC expected value:
        String jwe = Jwts.builder()
                .header().keyId(bobPrivJwk.getId()).and() //value will be "Dave" as noted above
                .setIssuer(issuer)
                .encryptWith(bobPrivJwk.toPublicJwk().toKey() as PublicKey, alg, Jwts.ENC.A256GCM)
                .compact()

        // the constructed JWE should have the following protected header:
        String rfcExpectedProtectedHeaderJson = RfcTests.stripws('''
        {
          "alg": "ECDH-ES+A256KW",
          "epk": {
            "kty": "OKP",
            "crv": "X448",
            "x": "mwj3zDG34-Z9ItWuoSEHSic70rg94Jxj-qc9LCLF2bvINmRyQdlT1AxbEtqIEg1TF3-A5TLEH6A"
          },
          "enc": "A256GCM", 
          "kid":"Dave"
        }''')

        String jweHeaderJson = new String(jwe.substring(0, jwe.indexOf('.')).decodeBase64Url(), StandardCharsets.UTF_8)

        // since JSON key/value ordering in JSON strings is not guaranteed, we change them to Maps and do equality
        // assertions that way:
        def rfcExpectedHeaderMap = RfcTests.jsonToMap(rfcExpectedProtectedHeaderJson)
        def jweHeaderMap = RfcTests.jsonToMap(jweHeaderJson)
        assertEquals(rfcExpectedHeaderMap, jweHeaderMap)
        assertEquals(rfcExpectedHeaderMap.get('epk'), jweHeaderMap.get('epk'))

        //ensure that Bob ("Dave") can decrypt:
        def jwt = Jwts.parser().decryptWith(bobPrivJwk.toKey() as PrivateKey).build().parseClaimsJwe(jwe)

        //assert that we've decrypted and the value in the body/content is as expected:
        assertEquals(issuer, jwt.getPayload().getIssuer())
    }
}
