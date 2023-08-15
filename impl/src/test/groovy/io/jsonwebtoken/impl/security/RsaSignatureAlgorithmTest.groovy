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
package io.jsonwebtoken.impl.security

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.impl.lang.CheckedFunction
import io.jsonwebtoken.security.InvalidKeyException
import io.jsonwebtoken.security.UnsupportedKeyException
import io.jsonwebtoken.security.WeakKeyException
import org.junit.Test

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

import static org.easymock.EasyMock.*
import static org.junit.Assert.*

class RsaSignatureAlgorithmTest {

    static final Collection<RsaSignatureAlgorithm> algs = Jwts.SIG.get().values().findAll({
        it instanceof RsaSignatureAlgorithm
    }) as Collection<RsaSignatureAlgorithm>

    @Test
    void testKeyPairBuilder() {
        algs.each {
            def pair = it.keyPair().build()
            assertNotNull pair.public
            assertTrue pair.public instanceof RSAPublicKey
            assertEquals it.preferredKeyBitLength, pair.public.modulus.bitLength()
            assertTrue pair.private instanceof RSAPrivateKey
            assertEquals it.preferredKeyBitLength, pair.private.modulus.bitLength()
        }
    }

    @Test
    void testValidateKeyWithoutRsaKey() {
        PublicKey key = createMock(PublicKey)
        replay key
        algs.each {
            it.validateKey(key, false)
            //no exception - can't check for RSAKey fields (e.g. PKCS11 or HSM key)
        }
        verify key
    }

    @Test
    void testValidateSigningKeyNotPrivate() {
        RSAPublicKey key = createMock(RSAPublicKey)
        def request = new DefaultSecureRequest(new byte[1], null, null, key)
        try {
            Jwts.SIG.RS256.digest(request)
            fail()
        } catch (InvalidKeyException e) {
            String expected = "RS256 signing keys must be PrivateKeys (implement java.security.PrivateKey). " +
                    "Provided key type: ${key.getClass().getName()}."
            assertEquals expected, e.getMessage()
        }
    }

    @Test
    void testValidateSigningKeyWeakKey() {
        def gen = KeyPairGenerator.getInstance("RSA")
        gen.initialize(1024) //too week for any JWA RSA algorithm
        def rsaPair = gen.generateKeyPair()

        def provider = RsaSignatureAlgorithm.PS256.getProvider() // in case BC was loaded
        def pssPair = new JcaTemplate(RsaSignatureAlgorithm.PSS_JCA_NAME, provider)
                .withKeyPairGenerator(new CheckedFunction<KeyPairGenerator, KeyPair>() {
                    @Override
                    KeyPair apply(KeyPairGenerator generator) throws Exception {
                        generator.initialize(1024)
                        return generator.generateKeyPair()
                    }
                })

        algs.each {
            def pair = it.getId().startsWith("PS") ? pssPair : rsaPair
            def request = new DefaultSecureRequest(new byte[1], null, null, pair.getPrivate())
            try {
                it.digest(request)
                fail()
            } catch (WeakKeyException expected) {
                String id = it.getId()
                String section = id.startsWith('PS') ? '3.5' : '3.3'
                String msg = "The signing key's size is 1024 bits which is not secure enough for the ${it.getId()} " +
                        "algorithm.  The JWT JWA Specification (RFC 7518, Section ${section}) states that RSA keys " +
                        "MUST have a size >= 2048 bits.  Consider using the Jwts.SIG.${id}.keyPair() " +
                        "builder to create a KeyPair guaranteed to be secure enough for ${id}.  See " +
                        "https://tools.ietf.org/html/rfc7518#section-${section} for more information."
                assertEquals msg, expected.getMessage()
            }
        }
    }

    @Test
    void testPssDigestUsingEncryptionKey() {

        def algs = Jwts.SIG.get().values()
                .findAll({it.id.startsWith('PS')})

        // standard RSA encryption key (not a RSASSA-PSS key):
        def pair = new JcaTemplate("RSA", null).generateKeyPair()

        for(def alg : algs) {
            def request = new DefaultSecureRequest(new byte[1], null, null, pair.getPrivate())
            try {
                alg.digest(request)
                fail()
            } catch (UnsupportedKeyException expected) {
                String msg = "RSA encryption keys should not be used with ${RsaSignatureAlgorithm.PSS_JCA_NAME} " +
                        "signature algorithms. Consider using the Jwts.SIG.${alg.id}.keyPair() builder to generate " +
                        "${RsaSignatureAlgorithm.PSS_JCA_NAME} KeyPairs suitable for use with the ${alg.id} " +
                        "signature algorithm."
                assertEquals msg, expected.getMessage()
            }
        }
    }

    @Test
    void testFindByKeyWithNoAlgorithm() {
        assertNull RsaSignatureAlgorithm.findByKey(new TestPrivateKey())
    }

    @Test
    void testFindByKeyInvalidAlgorithm() {
        assertNull DefaultMacAlgorithm.findByKey(new TestPrivateKey(algorithm: 'foo'))
    }

    @Test
    void testFindByKey() {
        for (def alg : algs) {
            def pair = TestKeys.forAlgorithm(alg).pair
            assertSame alg, RsaSignatureAlgorithm.findByKey(pair.public)
            assertSame alg, RsaSignatureAlgorithm.findByKey(pair.private)
        }
    }

    @Test
    void testFindByKeyNull() {
        assertNull RsaSignatureAlgorithm.findByKey(null)
    }

    @Test
    void testFindByNonAsymmetricKey() {
        assertNull RsaSignatureAlgorithm.findByKey(TestKeys.HS256)
    }

    @Test
    void testFindByWeakKey() {
        for (def alg : algs) {
            def pair = TestKeys.forAlgorithm(alg).pair
            byte[] mag = new byte[255] // one byte less than 256 (2048 bits) which is the minimum
            Randoms.secureRandom().nextBytes(mag)
            def modulus = new BigInteger(1, mag)
            //def modulus = pair.public.modulus
            def weakPub = new TestRSAKey(pair.public); weakPub.modulus = modulus
            def weakPriv = new TestRSAKey(pair.private); weakPriv.modulus = modulus
            assertNull RsaSignatureAlgorithm.findByKey(weakPub)
            assertNull RsaSignatureAlgorithm.findByKey(weakPriv)
        }
    }

    @Test
    void testFindByLargerThanExpectedKey() {
        for (def alg : algs) {
            def pair = TestKeys.forAlgorithm(alg).pair
            def mag = new byte[(alg.preferredKeyBitLength / Byte.SIZE) + 1] // one byte more than required
            Randoms.secureRandom().nextBytes(mag)
            def modulus = new BigInteger(1, mag)
            def strongPub = new TestRSAKey(pair.public); strongPub.modulus = modulus
            def strongPriv = new TestRSAKey(pair.private); strongPriv.modulus = modulus
            assertSame alg, RsaSignatureAlgorithm.findByKey(strongPub)
            assertSame alg, RsaSignatureAlgorithm.findByKey(strongPriv)
        }
    }

    @Test
    void testFindByKeyOid() {
        for (def entry : RsaSignatureAlgorithm.PKCSv15_ALGS.entrySet()) {
            def oid = entry.getKey()
            def alg = entry.getValue()
            def oidKey = new TestPrivateKey(algorithm: oid)
            assertSame alg, RsaSignatureAlgorithm.findByKey(oidKey)
        }
    }
}
