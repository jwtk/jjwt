package io.jsonwebtoken.impl.security


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
    void testDecryptionWithoutEcPublicJwk() {

        def alg = new EcdhKeyAlgorithm()
        ECPrivateKey decryptionKey = TestKeys.ES256.pair.private as ECPrivateKey

        def header = new DefaultJweHeader()
        def jwk = Jwks.builder().setKey(TestKeys.HS256).build() //something other than an EC public key
        header.put('epk', jwk)

        DecryptionKeyRequest req = new DefaultDecryptionKeyRequest(null, null, decryptionKey, header, EncryptionAlgorithms.A128GCM, 'test'.getBytes())

        try {
            alg.getDecryptionKey(req)
            fail()
        } catch (InvalidKeyException expected) {
            assertEquals("JWE Header 'epk' (Ephemeral Public Key) value is not an EllipticCurve Public JWK as required.", expected.getMessage())
        }
    }

    @Test
    void testDecryptionWithEcPublicJwkWithInvalidPoint() {

        def alg = new EcdhKeyAlgorithm()
        ECPrivateKey decryptionKey = TestKeys.ES256.pair.private as ECPrivateKey // Expected curve for this is P-256

        def header = new DefaultJweHeader()
        def pubJwk = Jwks.builder().setKey(TestKeys.ES256.pair.public as ECPublicKey).build()
        def jwk = new LinkedHashMap(pubJwk) // copy fields so we can mutate
        // We have a public JWK for a point on the curve, now swap out the x coordinate for something invalid:
        jwk.put('x', 'Kg')

        // now set the epk header as the invalid/manipulated jwk:
        header.put('epk', jwk)

        DecryptionKeyRequest req = new DefaultDecryptionKeyRequest(null, null, decryptionKey,
                header, EncryptionAlgorithms.A128GCM, 'test'.getBytes())

        try {
            alg.getDecryptionKey(req)
            fail()
        } catch (InvalidKeyException expected) {
            String msg = expected.getMessage()
            String expectedMsg = String.format(EcPublicJwkFactory.JWK_CONTAINS_FORMAT_MSG, pubJwk.crv, jwk)
            assertEquals(expectedMsg, msg)
        }
    }

    @Test
    void testDecryptionWithEcPublicJwkOnInvalidCurve() {

        def alg = new EcdhKeyAlgorithm()
        ECPrivateKey decryptionKey = TestKeys.ES256.pair.private as ECPrivateKey // Expected curve for this is P-256

        def header = new DefaultJweHeader()
        // This uses curve P-384 instead, does not match private key, so it's unexpected:
        def jwk = Jwks.builder().setKey(TestKeys.ES384.pair.public as ECPublicKey).build()
        header.put('epk', jwk)

        DecryptionKeyRequest req = new DefaultDecryptionKeyRequest(null, null, decryptionKey, header, EncryptionAlgorithms.A128GCM, 'test'.getBytes())

        try {
            alg.getDecryptionKey(req)
            fail()
        } catch (InvalidKeyException expected) {
            assertEquals("JWE Header 'epk' (Ephemeral Public Key) value does not represent a point on the expected curve.", expected.getMessage())
        }
    }
}
