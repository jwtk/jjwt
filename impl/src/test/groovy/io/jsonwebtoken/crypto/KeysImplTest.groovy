package io.jsonwebtoken.crypto

import io.jsonwebtoken.SignatureAlgorithm
import org.junit.Test

import javax.crypto.SecretKey
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey

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

            int bitLength = name.equalsIgnoreCase("NONE") ? 0 : name.substring(2).toInteger()

            if (name.startsWith('H')) {
                SecretKey key = Keys.secretKeyFor(alg)
                assertEquals bitLength, key.getEncoded().length * 8 //convert byte count to bit count
                assertEquals alg.jcaName, key.algorithm
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
            int bitLength = name.equalsIgnoreCase("NONE") ? 0 : name.substring(2).toInteger()

            if (name.startsWith('R') || name.startsWith('P')) {

                KeyPair pair = Keys.keyPairFor(alg)
                assertNotNull pair
                PublicKey pub = pair.getPublic()
                PrivateKey priv = pair.getPrivate()
                assert priv instanceof RSAPrivateKey
                assertEquals alg.familyName, pub.algorithm
                assertEquals alg.familyName, priv.algorithm
                assertEquals bitLength * 8, priv.modulus.bitLength()

            } else if (name.startsWith('E')) {

                KeyPair pair = Keys.keyPairFor(alg);
                assertNotNull pair

                if (alg == SignatureAlgorithm.ES512) {
                    bitLength = 521
                }

                String asn1oid = "secp${bitLength}r1"

                PublicKey pub = pair.getPublic()
                assert pub instanceof ECPublicKey
                assertEquals "ECDSA", pub.algorithm
                assertEquals asn1oid, pub.params.name
                assertEquals bitLength, pub.params.order.bitLength()

                PrivateKey priv = pair.getPrivate()
                assert priv instanceof ECPrivateKey
                assertEquals "ECDSA", priv.algorithm
                assertEquals asn1oid, priv.params.name

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
