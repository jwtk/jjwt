/*
 * Copyright (C) 2018 jsonwebtoken.io
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
//file:noinspection SpellCheckingInspection
package io.jsonwebtoken.impl.security

import io.jsonwebtoken.JwtException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.impl.lang.Bytes
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.security.InvalidKeyException
import io.jsonwebtoken.security.SignatureException
import org.junit.Test

import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.EllipticCurve
import java.security.spec.X509EncodedKeySpec

import static org.easymock.EasyMock.*
import static org.junit.Assert.*

class EcSignatureAlgorithmTest {

    static Collection<EcSignatureAlgorithm> algs() {
        return Jwts.SIG.get().values().findAll({ it instanceof EcSignatureAlgorithm }) as Collection<EcSignatureAlgorithm>
    }

    @Test
    void testConstructorWithWeakKeyLength() {
        try {
            new EcSignatureAlgorithm(128, 'foo')
        } catch (IllegalArgumentException iae) {
            String msg = 'orderBitLength must equal 256, 384, or 521.'
            assertEquals msg, iae.getMessage()
        }
    }

    @Test
    void testFindByNoAlgKey() {
        assertNull EcSignatureAlgorithm.findByKey(new TestKey())
    }

    @Test
    void testFindOidKeys() {
        for (def alg : EcSignatureAlgorithm.BY_OID.values()) {
            String name = "${alg.getId()}_OID"
            String oid = EcSignatureAlgorithm.metaClass.getAttribute(EcSignatureAlgorithm, name) as String
            assertEquals oid, alg.OID
            def key = new TestKey(algorithm: oid)
            assertSame alg, EcSignatureAlgorithm.findByKey(key)
        }
    }

    @Test
    void testFindByWeakKey() {
        ECPublicKey key = createMock(ECPublicKey)
        ECParameterSpec spec = createMock(ECParameterSpec)
        expect(key.getAlgorithm()).andStubReturn("EC")
        expect(key.getParams()).andStubReturn(spec)
        expect(spec.getOrder()).andStubReturn(BigInteger.ONE)
        replay key, spec
        assertNull EcSignatureAlgorithm.findByKey(key)
        verify key, spec
    }

    @Test
    void testValidateKeyWithoutECOrECDSAAlgorithmName() {
        PublicKey key = new TestPublicKey(algorithm: 'foo')
        algs().each {
            try {
                it.validateKey(key, false)
            } catch (InvalidKeyException e) {
                String msg = 'Unrecognized EC key algorithm name.'
                assertEquals msg, e.getMessage()
            }
        }
    }

    @Test
    void testValidateECAlgorithmKeyThatDoesntUseECKeyInterface() {
        PublicKey key = new TestPublicKey(algorithm: 'EC')
        algs().each {
            it.validateKey(key, false) //no exception - can't check for ECKey params (e.g. PKCS11 or HSM key)
        }
    }

    @Test
    void testIsValidRAndSWithoutEcKey() {
        PublicKey key = createMock(PublicKey)
        replay key
        algs().each {
            it.isValidRAndS(key, Bytes.EMPTY)
            //no exception - can't check for ECKey params (e.g. PKCS11 or HSM key)
        }
        verify key
    }

    @Test
    void testSignWithPublicKey() {
        ECPublicKey key = TestKeys.ES256.pair.public as ECPublicKey
        def request = new DefaultSecureRequest(new byte[1], null, null, key)
        def alg = Jwts.SIG.ES256
        try {
            alg.digest(request)
        } catch (InvalidKeyException e) {
            String msg = "${alg.getId()} signing keys must be PrivateKeys (implement ${PrivateKey.class.getName()}). " +
                    "Provided key type: ${key.getClass().getName()}."
            assertEquals msg, e.getMessage()
        }
    }

    @Test
    void testSignWithWeakKey() {
        algs().each {
            BigInteger order = BigInteger.ONE
            ECParameterSpec spec = new ECParameterSpec(new EllipticCurve(new TestECField(), BigInteger.ONE, BigInteger.ONE), new ECPoint(BigInteger.ONE, BigInteger.ONE), order, 1)
            ECPrivateKey priv = new TestECPrivateKey(algorithm: 'EC', params: spec)
            def request = new DefaultSecureRequest(new byte[1], null, null, priv)
            try {
                it.digest(request)
            } catch (InvalidKeyException expected) {
                String msg = "The provided Elliptic Curve signing key size (aka order bit length) is " +
                        "${Bytes.bitsMsg(order.bitLength())}, but the '${it.getId()}' algorithm requires EC Keys with " +
                        "${Bytes.bitsMsg(it.orderBitLength)} per " +
                        "[RFC 7518, Section 3.4](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4)." as String
                assertEquals msg, expected.getMessage()
            }
        }
    }

    @Test
    void testSignWithInvalidKeyFieldLength() {
        def keypair = Jwts.SIG.ES256.keyPair().build()
        def data = "foo".getBytes(StandardCharsets.UTF_8)
        def req = new DefaultSecureRequest(data, null, null, keypair.private)
        try {
            Jwts.SIG.ES384.digest(req)
        } catch (InvalidKeyException expected) {
            String msg = "The provided Elliptic Curve signing key size (aka order bit length) is " +
                    "256 bits (32 bytes), but the 'ES384' algorithm requires EC Keys with " +
                    "384 bits (48 bytes) per " +
                    "[RFC 7518, Section 3.4](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4)."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testVerifyWithPrivateKey() {
        byte[] data = 'foo'.getBytes(StandardCharsets.UTF_8)
        algs().each {
            def pair = it.keyPair().build()
            def key = pair.getPrivate()
            def signRequest = new DefaultSecureRequest(data, null, null, key)
            byte[] signature = it.digest(signRequest)
            def verifyRequest = new DefaultVerifySecureDigestRequest(data, null, null, key, signature)
            try {
                it.verify(verifyRequest)
            } catch (InvalidKeyException e) {
                String msg = "${it.getId()} verification keys must be PublicKeys (implement " +
                        "${PublicKey.class.name}). Provided key type: ${key.class.name}."
                assertEquals msg, e.getMessage()
            }
        }
    }

    @Test
    void testVerifyWithWeakKey() {
        algs().each {
            BigInteger order = BigInteger.ONE
            ECParameterSpec spec = new ECParameterSpec(new EllipticCurve(new TestECField(), BigInteger.ONE, BigInteger.ONE), new ECPoint(BigInteger.ONE, BigInteger.ONE), order, 1)
            ECPublicKey pub = new TestECPublicKey(algorithm: 'EC', params: spec)
            def request = new DefaultVerifySecureDigestRequest(new byte[1], null, null, pub, new byte[1])
            try {
                it.verify(request)
            } catch (InvalidKeyException expected) {
                String msg = "The provided Elliptic Curve verification key size (aka order bit length) is " +
                        "${Bytes.bitsMsg(order.bitLength())}, but the '${it.getId()}' algorithm requires EC Keys with " +
                        "${Bytes.bitsMsg(it.orderBitLength)} per " +
                        "[RFC 7518, Section 3.4](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4)." as String
                assertEquals msg, expected.getMessage()
            }
        }
    }

    @Test
    void invalidDERSignatureToJoseFormatTest() {
        def verify = { byte[] signature ->
            try {
                EcSignatureAlgorithm.transcodeDERToConcat(signature, 132)
                fail()
            } catch (JwtException e) {
                assertEquals e.message, 'Invalid ECDSA signature format'
            }
        }
        def signature = new byte[257]
        Randoms.secureRandom().nextBytes(signature)
        //invalid type
        signature[0] = 34
        verify(signature)
        def shortSignature = new byte[7]
        Randoms.secureRandom().nextBytes(shortSignature)
        verify(shortSignature)
        signature[0] = 48
//        signature[1] = 0x81
        signature[1] = -10
        verify(signature)
    }

    @Test
    void edgeCaseSignatureToConcatInvalidSignatureTest() {
        try {
            def signature = Decoders.BASE64.decode("MIGBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            EcSignatureAlgorithm.transcodeDERToConcat(signature, 132)
            fail()
        } catch (JwtException e) {
            assertEquals e.message, 'Invalid ECDSA signature format'
        }
    }

    @Test
    void edgeCaseSignatureToConcatInvalidSignatureBranchTest() {
        try {
            def signature = Decoders.BASE64.decode("MIGBAD4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            EcSignatureAlgorithm.transcodeDERToConcat(signature, 132)
            fail()
        } catch (JwtException e) {
            assertEquals e.message, 'Invalid ECDSA signature format'
        }
    }

    @Test
    void edgeCaseSignatureToConcatInvalidSignatureBranch2Test() {
        try {
            def signature = Decoders.BASE64.decode("MIGBAj4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            EcSignatureAlgorithm.transcodeDERToConcat(signature, 132)
            fail()
        } catch (JwtException e) {
            assertEquals e.message, 'Invalid ECDSA signature format'
        }
    }

    @Test
    void edgeCaseSignatureToConcatLengthTest() {
        try {
            def signature = Decoders.BASE64.decode("MIEAAGg3OVb/ZeX12cYrhK3c07TsMKo7Kc6SiqW++4CAZWCX72DkZPGTdCv2duqlupsnZL53hiG3rfdOLj8drndCU+KHGrn5EotCATdMSLCXJSMMJoHMM/ZPG+QOHHPlOWnAvpC1v4lJb32WxMFNz1VAIWrl9Aa6RPG1GcjCTScKjvEE")
            EcSignatureAlgorithm.transcodeDERToConcat(signature, 132)
            fail()
        } catch (JwtException expected) {
        }
    }

    @Test
    void invalidECDSASignatureFormatTest() {
        try {
            def signature = new byte[257]
            Randoms.secureRandom().nextBytes(signature)
            EcSignatureAlgorithm.transcodeConcatToDER(signature)
            fail()
        } catch (JwtException e) {
            assertEquals 'Invalid ECDSA signature format.', e.message
        }
    }

    @Test
    void edgeCaseSignatureLengthTest() {
        def signature = new byte[1]
        EcSignatureAlgorithm.transcodeConcatToDER(signature)
    }

    @Test
    void testPaddedSignatureToDER() {
        def signature = new byte[32]
        Randoms.secureRandom().nextBytes(signature)
        signature[0] = 0 as byte
        EcSignatureAlgorithm.transcodeConcatToDER(signature) //no exception
    }

    @Test
    void ecdsaSignatureCompatTest() {
        def fact = KeyFactory.getInstance("EC")
        def publicKey = "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQASisgweVL1tAtIvfmpoqvdXF8sPKTV9YTKNxBwkdkm+/auh4pR8TbaIfsEzcsGUVv61DFNFXb0ozJfurQ59G2XcgAn3vROlSSnpbIvuhKrzL5jwWDTaYa5tVF1Zjwia/5HUhKBkcPuWGXg05nMjWhZfCuEetzMLoGcHmtvabugFrqsAg="
        def pub = fact.generatePublic(new X509EncodedKeySpec(Decoders.BASE64.decode(publicKey)))
        def alg = Jwts.SIG.ES512
        def verifier = { String token ->
            def signatureStart = token.lastIndexOf('.')
            def withoutSignature = token.substring(0, signatureStart)
            def data = withoutSignature.getBytes("US-ASCII")
            def signature = Decoders.BASE64URL.decode(token.substring(signatureStart + 1))
            assertTrue "Signature do not match that of other implementations", alg.verify(new DefaultVerifySecureDigestRequest(data, null, null, pub, signature))
        }
        //Test verification for token created using https://github.com/auth0/node-jsonwebtoken/tree/v7.0.1
        verifier("eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoidGVzdCIsImlhdCI6MTQ2NzA2NTgyN30.Aab4x7HNRzetjgZ88AMGdYV2Ml7kzFbl8Ql2zXvBores7iRqm2nK6810ANpVo5okhHa82MQf2Q_Zn4tFyLDR9z4GAcKFdcAtopxq1h8X58qBWgNOc0Bn40SsgUc8wOX4rFohUCzEtnUREePsvc9EfXjjAH78WD2nq4tn-N94vf14SncQ")
        //Test verification for token created using https://github.com/jwt/ruby-jwt/tree/v1.5.4
        verifier("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.eyJ0ZXN0IjoidGVzdCJ9.AV26tERbSEwcoDGshneZmhokg-tAKUk0uQBoHBohveEd51D5f6EIs6cskkgwtfzs4qAGfx2rYxqQXr7LTXCNquKiAJNkTIKVddbPfped3_TQtmHZTmMNiqmWjiFj7Y9eTPMMRRu26w4gD1a8EQcBF-7UGgeH4L_1CwHJWAXGbtu7uMUn")
    }

    @Test
    void verifySwarmTest() {
        algs().each { alg ->
            def withoutSignature = "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoidGVzdCIsImlhdCI6MTQ2NzA2NTgyN30"
            def keypair = alg.keyPair().build()
            assertNotNull keypair
            assertTrue keypair.getPublic() instanceof ECPublicKey
            assertTrue keypair.getPrivate() instanceof ECPrivateKey
            def data = withoutSignature.getBytes("US-ASCII")
            def signature = alg.digest(new DefaultSecureRequest<>(data, null, null, keypair.private))
            assertTrue alg.verify(new DefaultVerifySecureDigestRequest(data, null, null, keypair.public, signature))
        }
    }

    // ===================== Begin imported EllipticCurveSignerTest test cases ==============================

    /*

    @Test
    void testDoSignWithInvalidKeyException() {

        SignatureAlgorithm alg = SignatureAlgorithm.ES256

        KeyPair kp = Keys.keyPairFor(alg)
        PrivateKey privateKey = kp.getPrivate()

        String msg = 'foo'
        final java.security.InvalidKeyException ex = new java.security.InvalidKeyException(msg)

        def signer = new EllipticCurveSigner(alg, privateKey) {
            @Override
            protected byte[] doSign(byte[] data) throws java.security.InvalidKeyException, java.security.SignatureException {
                throw ex
            }
        }

        byte[] bytes = new byte[16]
        SignatureProvider.DEFAULT_SECURE_RANDOM.nextBytes(bytes)

        try {
            signer.digest(bytes)
            fail();
        } catch (io.jsonwebtoken.security.SignatureException se) {
            assertEquals se.message, 'Invalid Elliptic Curve PrivateKey. ' + msg
            assertSame se.cause, ex
        }
    }

    @Test
    void testDoSignWithJoseSignatureFormatException() {

        SignatureAlgorithm alg = SignatureAlgorithm.ES256
        KeyPair kp = EllipticCurveProvider.generateKeyPair(alg)
        PublicKey publicKey = kp.getPublic();
        PrivateKey privateKey = kp.getPrivate();

        String msg = 'foo'
        final JwtException ex = new JwtException(msg)

        def signer = new EllipticCurveSigner(alg, privateKey) {
            @Override
            protected byte[] doSign(byte[] data) throws java.security.InvalidKeyException, java.security.SignatureException, JwtException {
                throw ex
            }
        }

        byte[] bytes = new byte[16]
        SignatureProvider.DEFAULT_SECURE_RANDOM.nextBytes(bytes)

        try {
            signer.digest(bytes)
            fail();
        } catch (io.jsonwebtoken.security.SignatureException se) {
            assertEquals se.message, 'Unable to convert signature to JOSE format. ' + msg
            assertSame se.cause, ex
        }
    }

    @Test
    void testDoSignWithJdkSignatureException() {

        SignatureAlgorithm alg = SignatureAlgorithm.ES256
        KeyPair kp = EllipticCurveProvider.generateKeyPair(alg)
        PublicKey publicKey = kp.getPublic();
        PrivateKey privateKey = kp.getPrivate();

        String msg = 'foo'
        final java.security.SignatureException ex = new java.security.SignatureException(msg)

        def signer = new EllipticCurveSigner(alg, privateKey) {
            @Override
            protected byte[] doSign(byte[] data) throws java.security.InvalidKeyException, java.security.SignatureException {
                throw ex
            }
        }

        byte[] bytes = new byte[16]
        SignatureProvider.DEFAULT_SECURE_RANDOM.nextBytes(bytes)

        try {
            signer.digest(bytes)
            fail();
        } catch (io.jsonwebtoken.security.SignatureException se) {
            assertEquals se.message, 'Unable to calculate signature using Elliptic Curve PrivateKey. ' + msg
            assertSame se.cause, ex
        }
    }

    @Test
    void testDoVerifyWithInvalidKeyException() {

        String msg = 'foo'
        final java.security.InvalidKeyException ex = new java.security.InvalidKeyException(msg)
        def alg = SignatureAlgorithm.ES512
        def keypair = EllipticCurveProvider.generateKeyPair(alg)

        def v = new EllipticCurveSignatureValidator(alg, EllipticCurveProvider.generateKeyPair(alg).public) {
            @Override
            protected boolean doVerify(Signature sig, PublicKey pk, byte[] data, byte[] signature) throws java.security.InvalidKeyException, java.security.SignatureException {
                throw ex;
            }
        }

        byte[] data = new byte[32]
        SignatureProvider.DEFAULT_SECURE_RANDOM.nextBytes(data)

        byte[] signature = new EllipticCurveSigner(alg, keypair.getPrivate()).digest(data)

        try {
            v.isValid(data, signature)
            fail();
        } catch (io.jsonwebtoken.security.SignatureException se) {
            assertEquals se.message, 'Unable to verify Elliptic Curve signature using configured ECPublicKey. ' + msg
            assertSame se.cause, ex
        }
    }

     */

    @Test
    void ecdsaSignatureInteropTest() {
        def fact = KeyFactory.getInstance("EC")
        def publicKey = "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQASisgweVL1tAtIvfmpoqvdXF8sPKTV9YTKNxBwkdkm+/auh4pR8TbaIfsEzcsGUVv61DFNFXb0ozJfurQ59G2XcgAn3vROlSSnpbIvuhKrzL5jwWDTaYa5tVF1Zjwia/5HUhKBkcPuWGXg05nMjWhZfCuEetzMLoGcHmtvabugFrqsAg="
        def pub = fact.generatePublic(new X509EncodedKeySpec(Decoders.BASE64.decode(publicKey)))
        def alg = Jwts.SIG.ES512
        def verifier = { String token ->
            def signatureStart = token.lastIndexOf('.')
            def withoutSignature = token.substring(0, signatureStart)
            def signature = token.substring(signatureStart + 1)

            def data = withoutSignature.getBytes(StandardCharsets.US_ASCII)
            def sigBytes = Decoders.BASE64URL.decode(signature)
            def request = new DefaultVerifySecureDigestRequest(data, null, null, pub, sigBytes)
            assert alg.verify(request), "Signature do not match that of other implementations"
        }
        //Test verification for token created using https://github.com/auth0/node-jsonwebtoken/tree/v7.0.1
        verifier("eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoidGVzdCIsImlhdCI6MTQ2NzA2NTgyN30.Aab4x7HNRzetjgZ88AMGdYV2Ml7kzFbl8Ql2zXvBores7iRqm2nK6810ANpVo5okhHa82MQf2Q_Zn4tFyLDR9z4GAcKFdcAtopxq1h8X58qBWgNOc0Bn40SsgUc8wOX4rFohUCzEtnUREePsvc9EfXjjAH78WD2nq4tn-N94vf14SncQ")
        //Test verification for token created using https://github.com/jwt/ruby-jwt/tree/v1.5.4
        verifier("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.eyJ0ZXN0IjoidGVzdCJ9.AV26tERbSEwcoDGshneZmhokg-tAKUk0uQBoHBohveEd51D5f6EIs6cskkgwtfzs4qAGfx2rYxqQXr7LTXCNquKiAJNkTIKVddbPfped3_TQtmHZTmMNiqmWjiFj7Y9eTPMMRRu26w4gD1a8EQcBF-7UGgeH4L_1CwHJWAXGbtu7uMUn")
    }

    @Test
    // asserts guard for JVM security bug CVE-2022-21449:
    void legacySignatureCompatDefaultTest() {
        def withoutSignature = "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoidGVzdCIsImlhdCI6MTQ2NzA2NTgyN30"
        def alg = Jwts.SIG.ES512
        def keypair = alg.keyPair().build()
        def signature = Signature.getInstance(alg.jcaName as String)
        def data = withoutSignature.getBytes(StandardCharsets.US_ASCII)
        signature.initSign(keypair.private)
        signature.update(data)
        def signed = signature.sign()
        def request = new DefaultVerifySecureDigestRequest(data, null, null, keypair.public, signed)
        try {
            alg.verify(request)
            fail()
        } catch (SignatureException expected) {
            String signedBytesString = Bytes.bytesMsg(signed.length)
            String msg = "Unable to verify Elliptic Curve signature using provided ECPublicKey: Provided " +
                    "signature is $signedBytesString but ES512 signatures must be exactly 1056 bits (132 bytes) " +
                    "per [RFC 7518, Section 3.4 (validation)]" +
                    "(https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4)." as String
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void legacySignatureCompatWhenEnabledTest() {
        try {
            System.setProperty(EcSignatureAlgorithm.DER_ENCODING_SYS_PROPERTY_NAME, 'true')

            def withoutSignature = "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoidGVzdCIsImlhdCI6MTQ2NzA2NTgyN30"
            def alg = Jwts.SIG.ES512
            def keypair = alg.keyPair().build()
            def signature = Signature.getInstance(alg.jcaName as String)
            def data = withoutSignature.getBytes(StandardCharsets.US_ASCII)
            signature.initSign(keypair.private)
            signature.update(data)
            def signed = signature.sign()
            def request = new DefaultVerifySecureDigestRequest(data, null, null, keypair.public, signed)
            assertTrue alg.verify(request)
        } finally {
            System.clearProperty(EcSignatureAlgorithm.DER_ENCODING_SYS_PROPERTY_NAME)
        }
    }

    @Test
    // asserts guard for JVM security bug CVE-2022-21449:
    void testVerifySignatureAllZeros() {
        byte[] forgedSig = new byte[64]
        def withoutSignature = "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoidGVzdCIsImlhdCI6MTQ2NzA2NTgyN30"
        def alg = Jwts.SIG.ES256
        def keypair = alg.keyPair().build()
        def data = withoutSignature.getBytes(StandardCharsets.US_ASCII)
        def request = new DefaultVerifySecureDigestRequest(data, null, null, keypair.public, forgedSig)
        assertFalse alg.verify(request)
    }

    @Test
    // asserts guard for JVM security bug CVE-2022-21449:
    void testVerifySignatureRZero() {
        byte[] r = new byte[32]
        byte[] s = new byte[32]; Arrays.fill(s, Byte.MAX_VALUE)
        byte[] sig = new byte[r.length + s.length]
        System.arraycopy(r, 0, sig, 0, r.length)
        System.arraycopy(s, 0, sig, r.length, s.length)

        def withoutSignature = "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoidGVzdCIsImlhdCI6MTQ2NzA2NTgyN30"
        def alg = Jwts.SIG.ES256
        def keypair = alg.keyPair().build()
        def data = withoutSignature.getBytes(StandardCharsets.US_ASCII)
        def request = new DefaultVerifySecureDigestRequest(data, null, null, keypair.public, sig)
        assertFalse alg.verify(request)
    }

    @Test
    // asserts guard for JVM security bug CVE-2022-21449:
    void testVerifySignatureSZero() {
        byte[] r = new byte[32]; Arrays.fill(r, Byte.MAX_VALUE)
        byte[] s = new byte[32]
        byte[] sig = new byte[r.length + s.length]
        System.arraycopy(r, 0, sig, 0, r.length)
        System.arraycopy(s, 0, sig, r.length, s.length)

        def withoutSignature = "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoidGVzdCIsImlhdCI6MTQ2NzA2NTgyN30"
        def alg = Jwts.SIG.ES256
        def keypair = alg.keyPair().build()
        def data = withoutSignature.getBytes(StandardCharsets.US_ASCII)
        def request = new DefaultVerifySecureDigestRequest(data, null, null, keypair.public, sig)
        assertFalse alg.verify(request)
    }

    @Test
    // asserts guard for JVM security bug CVE-2022-21449:
    void ecdsaInvalidSignatureValuesTest() {
        def withoutSignature = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoidGVzdCIsImlhdCI6MTQ2NzA2NTgyN30"
        def invalidEncodedSignature = "_____wAAAAD__________7zm-q2nF56E87nKwvxjJVH_____AAAAAP__________vOb6racXnoTzucrC_GMlUQ"
        def alg = Jwts.SIG.ES256
        def keypair = alg.keyPair().build()
        def data = withoutSignature.getBytes(StandardCharsets.US_ASCII)
        def invalidSignature = Decoders.BASE64URL.decode(invalidEncodedSignature)
        def request = new DefaultVerifySecureDigestRequest(data, null, null, keypair.public, invalidSignature)
        assertFalse("Forged signature must not be considered valid.", alg.verify(request))
    }
}
