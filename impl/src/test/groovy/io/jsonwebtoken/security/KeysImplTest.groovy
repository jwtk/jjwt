/*
 * Copyright (C) 2014 jsonwebtoken.io
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
                def keyAlgName = alg.jcaName.equals("RSASSA-PSS") ? "RSASSA-PSS" : alg.familyName
                assertEquals keyAlgName, pub.algorithm
                assertEquals alg.digestLength * 8, pub.modulus.bitLength()

                PrivateKey priv = pair.getPrivate()
                assert priv instanceof RSAPrivateKey
                assertEquals keyAlgName, priv.algorithm
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
                if (pub.params.hasProperty('name')) { // JDK <= 14
                    assertEquals jdkParamName, pub.params.name
                } else { // JDK >= 15
                    assertEquals asn1oid, pub.params.nameAndAliases[0]
                }
                assertEquals alg.minKeyLength, pub.params.order.bitLength()

                PrivateKey priv = pair.getPrivate()
                assert priv instanceof ECPrivateKey
                assertEquals "EC", priv.algorithm
                if (pub.params.hasProperty('name')) { // JDK <= 14
                    assertEquals jdkParamName, priv.params.name
                } else { // JDK >= 15
                    assertEquals asn1oid, priv.params.nameAndAliases[0]
                }
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
