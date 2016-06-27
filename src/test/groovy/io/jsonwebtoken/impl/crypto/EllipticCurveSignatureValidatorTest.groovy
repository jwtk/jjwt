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
import io.jsonwebtoken.impl.TextCodec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Test

import java.security.*
import java.security.spec.X509EncodedKeySpec

import static org.junit.Assert.*

class EllipticCurveSignatureValidatorTest {

    static {
        Security.addProvider(new BouncyCastleProvider())
    }

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

    @Test
    void ecdsaSignatureComplianceTest() {
        def fact = KeyFactory.getInstance("ECDSA", "BC");
        def publicKey = "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQASisgweVL1tAtIvfmpoqvdXF8sPKTV9YTKNxBwkdkm+/auh4pR8TbaIfsEzcsGUVv61DFNFXb0ozJfurQ59G2XcgAn3vROlSSnpbIvuhKrzL5jwWDTaYa5tVF1Zjwia/5HUhKBkcPuWGXg05nMjWhZfCuEetzMLoGcHmtvabugFrqsAg="
        def pub = fact.generatePublic(new X509EncodedKeySpec(TextCodec.BASE64.decode(publicKey)))
        def v = new EllipticCurveSignatureValidator(SignatureAlgorithm.ES512, pub)
        def verifier = { token ->
            def signatureStart = token.lastIndexOf('.')
            def withoutSignature = token.substring(0, signatureStart)
            def signature = token.substring(signatureStart + 1)
            assert v.isValid(withoutSignature.getBytes("US-ASCII"), TextCodec.BASE64URL.decode(signature)), "Signature do not match that of other implementations"
        }
        //Test verification for token created using https://github.com/auth0/node-jsonwebtoken/tree/v7.0.1
        verifier("eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoidGVzdCIsImlhdCI6MTQ2NzA2NTgyN30.Aab4x7HNRzetjgZ88AMGdYV2Ml7kzFbl8Ql2zXvBores7iRqm2nK6810ANpVo5okhHa82MQf2Q_Zn4tFyLDR9z4GAcKFdcAtopxq1h8X58qBWgNOc0Bn40SsgUc8wOX4rFohUCzEtnUREePsvc9EfXjjAH78WD2nq4tn-N94vf14SncQ")
        //Test verification for token created using https://github.com/jwt/ruby-jwt/tree/v1.5.4
        verifier("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.eyJ0ZXN0IjoidGVzdCJ9.AV26tERbSEwcoDGshneZmhokg-tAKUk0uQBoHBohveEd51D5f6EIs6cskkgwtfzs4qAGfx2rYxqQXr7LTXCNquKiAJNkTIKVddbPfped3_TQtmHZTmMNiqmWjiFj7Y9eTPMMRRu26w4gD1a8EQcBF-7UGgeH4L_1CwHJWAXGbtu7uMUn")
    }
}
