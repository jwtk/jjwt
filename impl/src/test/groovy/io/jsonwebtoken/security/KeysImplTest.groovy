package io.jsonwebtoken.security

import io.jsonwebtoken.SignatureAlgorithm
import org.junit.Test

import javax.crypto.SecretKey
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

import static org.junit.Assert.*

class KeysImplTest {

    @Test
    void testPrivateCtor() { //for code coverage purposes only
        new Keys()
    }

    @Test
    void testSecretKeyFor() {

        for (SignatureAlgorithm alg : SignatureAlgorithm.values()) {

            String name = alg.name()

            if (alg.isHmac()) {
                SecretKey key = Keys.secretKeyFor(alg)
                assertEquals alg.minKeyLength, key.getEncoded().length * 8 //convert byte count to bit count
                assertEquals alg.jcaName, key.algorithm
                alg.assertValidSigningKey(key)
                alg.assertValidVerificationKey(key)
                assertEquals alg, SignatureAlgorithm.forSigningKey(key) // https://github.com/jwtk/jjwt/issues/381
            } else {
                try {
                    Keys.secretKeyFor(alg)
                    fail()
                } catch (IllegalArgumentException expected) {
                    assertEquals "The $name algorithm does not support shared secret keys." as String, expected.message
                }

            }
        }
    }

    @Test
    void testKeyPairFor() {

        for (SignatureAlgorithm alg : SignatureAlgorithm.values()) {

            String name = alg.name()

            if (alg.isRsa()) {

                KeyPair pair = Keys.keyPairFor(alg)
                assertNotNull pair

                PublicKey pub = pair.getPublic()
                assert pub instanceof RSAPublicKey
                assertEquals alg.familyName, pub.algorithm
                assertEquals alg.digestLength * 8, pub.modulus.bitLength()

                PrivateKey priv = pair.getPrivate()
                assert priv instanceof RSAPrivateKey
                assertEquals alg.familyName, priv.algorithm
                assertEquals alg.digestLength * 8, priv.modulus.bitLength()

            } else if (alg.isEllipticCurve()) {

                KeyPair pair = Keys.keyPairFor(alg);
                assertNotNull pair

                int len = alg.minKeyLength
                String asn1oid = "secp${len}r1"
                String suffix = len == 256 ? ", X9.62 prime${len}v1" : '' //the JDK only adds this extra suffix to the secp256r1 curve name and not secp384r1 or secp521r1 curve names
                String jdkParamName = "$asn1oid [NIST P-${len}${suffix}]" as String

                PublicKey pub = pair.getPublic()
                assert pub instanceof ECPublicKey
                assertEquals "EC", pub.algorithm
                assertEquals jdkParamName, pub.params.name
                assertEquals alg.minKeyLength, pub.params.order.bitLength()

                PrivateKey priv = pair.getPrivate()
                assert priv instanceof ECPrivateKey
                assertEquals "EC", priv.algorithm
                assertEquals jdkParamName, priv.params.name
                assertEquals alg.minKeyLength, priv.params.order.bitLength()

            } else {
                try {
                    Keys.keyPairFor(alg)
                    fail()
                } catch (IllegalArgumentException expected) {
                    assertEquals "The $name algorithm does not support Key Pairs." as String, expected.message
                }
            }
        }
    }
}
