package io.jsonwebtoken.impl.security

import io.jsonwebtoken.JwtException
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.security.InvalidKeyException
import io.jsonwebtoken.security.SignatureAlgorithms
import io.jsonwebtoken.security.WeakKeyException
import org.junit.Test

import javax.crypto.spec.SecretKeySpec
import java.nio.charset.StandardCharsets
import java.security.*
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec

import static org.easymock.EasyMock.createMock
import static org.junit.Assert.*

class EllipticCurveSignatureAlgorithmTest {

    @Test
    void testConstructorWithWeakKeyLength() {
        try {
            new EllipticCurveSignatureAlgorithm('ES256', 'SHA256withECDSA', 'secp256r1', 128, 256)
        } catch (IllegalArgumentException iae) {
            assertEquals 'minKeyLength bits must be greater than the JWA mandatory minimum key length of 256', iae.getMessage()
        }
    }

    @Test(expected=IllegalStateException)
    void testGenerateKeyPairInvalidCurveName() {
        def alg = new EllipticCurveSignatureAlgorithm('ES256', 'SHA256withECDSA', 'notreal', 256, 256)
        alg.generateKeyPair()
    }

    @Test
    void testValidateKeyEcKey() {
        def request = new DefaultCryptoRequest<byte[], Key>(new byte[1], new SecretKeySpec(new byte[1], 'foo'), null, null)
        try {
            SignatureAlgorithms.ES256.sign(request)
        } catch (InvalidKeyException e) {
            assertTrue e.getMessage().contains("must be an ECKey")
        }
    }

    @Test
    void testValidateSigningKeyNotPrivate() {
        ECPublicKey key = createMock(ECPublicKey)
        def request = new DefaultCryptoRequest<byte[], Key>(new byte[1], key, null, null)
        try {
            SignatureAlgorithms.ES256.sign(request)
        } catch (InvalidKeyException e) {
            assertTrue e.getMessage().startsWith("Asymmetric key signatures must be created with PrivateKeys. The specified key is of type: ")
        }
    }

    @Test
    void testValidateSigningKeyWeakKey() {
        def gen = KeyPairGenerator.getInstance("EC")
        gen.initialize(192) //too week for any JWA EC algorithm
        def pair = gen.generateKeyPair()

        def request = new DefaultCryptoRequest<byte[], Key>(new byte[1], pair.getPrivate(), null, null)
        SignatureAlgorithms.values().findAll({it.getName().startsWith('ES')}).each {
            try {
                it.sign(request)
            } catch (WeakKeyException expected) {
            }
        }
    }

    @Test
    void testVerifyWithPrivateKey() {
        byte[] data = 'foo'.getBytes(StandardCharsets.UTF_8)
        SignatureAlgorithms.values().findAll({it instanceof EllipticCurveSignatureAlgorithm}).each {
            KeyPair pair = it.generateKeyPair()
            def signRequest = new DefaultCryptoRequest(data, pair.getPrivate(), null, null)
            byte[] signature = it.sign(signRequest)
            def verifyRequest = new DefaultVerifySignatureRequest(data, pair.getPrivate(), null, null, signature)
            try {
                it.verify(verifyRequest)
            } catch (InvalidKeyException e) {
                assertEquals 'Elliptic Curve signature validation requires an ECPublicKey instance.', e.getMessage()
            }
        }
    }

    @Test
    void invalidDERSignatureToJoseFormatTest() {
        def verify = { signature ->
            try {
                EllipticCurveSignatureAlgorithm.transcodeSignatureToConcat(signature, 132)
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
            EllipticCurveSignatureAlgorithm.transcodeSignatureToConcat(signature, 132)
            fail()
        } catch (JwtException e) {
            assertEquals e.message, 'Invalid ECDSA signature format'
        }
    }

    @Test
    void edgeCaseSignatureToConcatInvalidSignatureBranchTest() {
        try {
            def signature = Decoders.BASE64.decode("MIGBAD4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            EllipticCurveSignatureAlgorithm.transcodeSignatureToConcat(signature, 132)
            fail()
        } catch (JwtException e) {
            assertEquals e.message, 'Invalid ECDSA signature format'
        }
    }

    @Test
    void edgeCaseSignatureToConcatInvalidSignatureBranch2Test() {
        try {
            def signature = Decoders.BASE64.decode("MIGBAj4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            EllipticCurveSignatureAlgorithm.transcodeSignatureToConcat(signature, 132)
            fail()
        } catch (JwtException e) {
            assertEquals e.message, 'Invalid ECDSA signature format'
        }
    }

    @Test
    void edgeCaseSignatureToConcatLengthTest() {
        try {
            def signature = Decoders.BASE64.decode("MIEAAGg3OVb/ZeX12cYrhK3c07TsMKo7Kc6SiqW++4CAZWCX72DkZPGTdCv2duqlupsnZL53hiG3rfdOLj8drndCU+KHGrn5EotCATdMSLCXJSMMJoHMM/ZPG+QOHHPlOWnAvpC1v4lJb32WxMFNz1VAIWrl9Aa6RPG1GcjCTScKjvEE")
            EllipticCurveSignatureAlgorithm.transcodeSignatureToConcat(signature, 132)
            fail()
        } catch (JwtException expected) {

        }
    }

    @Test
    void invalidECDSASignatureFormatTest() {
        try {
            def signature = new byte[257]
            Randoms.secureRandom().nextBytes(signature)
            EllipticCurveSignatureAlgorithm.transcodeSignatureToDER(signature)
            fail()
        } catch (JwtException e) {
            assertEquals e.message, 'Invalid ECDSA signature format'
        }
    }

    @Test
    void edgeCaseSignatureLengthTest() {
        def signature = new byte[1]
        EllipticCurveSignatureAlgorithm.transcodeSignatureToDER(signature)
    }

    @Test
    void testPaddedSignatureToDER() {
        def signature = new byte[32]
        Randoms.secureRandom().nextBytes(signature)
        signature[0] = 0 as byte
        EllipticCurveSignatureAlgorithm.transcodeSignatureToDER(signature) //no exception
    }

    @Test
    void ecdsaSignatureCompatTest() {
        def fact = KeyFactory.getInstance("EC");
        def publicKey = "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQASisgweVL1tAtIvfmpoqvdXF8sPKTV9YTKNxBwkdkm+/auh4pR8TbaIfsEzcsGUVv61DFNFXb0ozJfurQ59G2XcgAn3vROlSSnpbIvuhKrzL5jwWDTaYa5tVF1Zjwia/5HUhKBkcPuWGXg05nMjWhZfCuEetzMLoGcHmtvabugFrqsAg="
        def pub = fact.generatePublic(new X509EncodedKeySpec(Decoders.BASE64.decode(publicKey)))
        def alg = SignatureAlgorithms.ES512
        def verifier = { token ->
            def signatureStart = token.lastIndexOf('.')
            def withoutSignature = token.substring(0, signatureStart)
            def data = withoutSignature.getBytes("US-ASCII")
            def signature = Decoders.BASE64URL.decode(token.substring(signatureStart + 1))
            assertTrue"Signature do not match that of other implementations", alg.verify(new DefaultVerifySignatureRequest(data, pub, null, null, signature))
        }
        //Test verification for token created using https://github.com/auth0/node-jsonwebtoken/tree/v7.0.1
        verifier("eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoidGVzdCIsImlhdCI6MTQ2NzA2NTgyN30.Aab4x7HNRzetjgZ88AMGdYV2Ml7kzFbl8Ql2zXvBores7iRqm2nK6810ANpVo5okhHa82MQf2Q_Zn4tFyLDR9z4GAcKFdcAtopxq1h8X58qBWgNOc0Bn40SsgUc8wOX4rFohUCzEtnUREePsvc9EfXjjAH78WD2nq4tn-N94vf14SncQ")
        //Test verification for token created using https://github.com/jwt/ruby-jwt/tree/v1.5.4
        verifier("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.eyJ0ZXN0IjoidGVzdCJ9.AV26tERbSEwcoDGshneZmhokg-tAKUk0uQBoHBohveEd51D5f6EIs6cskkgwtfzs4qAGfx2rYxqQXr7LTXCNquKiAJNkTIKVddbPfped3_TQtmHZTmMNiqmWjiFj7Y9eTPMMRRu26w4gD1a8EQcBF-7UGgeH4L_1CwHJWAXGbtu7uMUn")
    }

    @Test
    void legacySignatureCompatTest() {
        def withoutSignature = "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoidGVzdCIsImlhdCI6MTQ2NzA2NTgyN30"
        def alg = SignatureAlgorithms.ES512
        def keypair = alg.generateKeyPair()
        def signature = Signature.getInstance(alg.jcaName)
        def data = withoutSignature.getBytes("US-ASCII")
        signature.initSign(keypair.private)
        signature.update(data)
        def signed = signature.sign()
        assertTrue alg.verify(new DefaultVerifySignatureRequest(data, keypair.public, null, null, signed))
    }

    @Test
    void verifySwarmTest() {
        SignatureAlgorithms.values().findAll({it.getName().startsWith('ES')}).each {alg ->
            def withoutSignature = "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoidGVzdCIsImlhdCI6MTQ2NzA2NTgyN30"
            def keypair = alg.generateKeyPair()
            def data = withoutSignature.getBytes("US-ASCII")
            def signature = alg.sign(new DefaultCryptoRequest<byte[], Key>(data, keypair.private, null, null))
            assertTrue alg.verify(new DefaultVerifySignatureRequest(data, keypair.public, null, null, signature))
        }
    }
}
