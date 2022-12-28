package io.jsonwebtoken.impl.security


import io.jsonwebtoken.security.InvalidKeyException
import io.jsonwebtoken.security.SignatureAlgorithms
import io.jsonwebtoken.security.WeakKeyException
import org.junit.Test

import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

import static org.easymock.EasyMock.*
import static org.junit.Assert.*

class DefaultRsaSignatureAlgorithmTest {

    static Collection<DefaultRsaSignatureAlgorithm> algs() {
        return SignatureAlgorithms.values().findAll({ it.id.startsWith("RS") || it.id.startsWith("PS") })
    }

    @Test
    void testKeyPairBuilder() {
        algs().each {
            def pair = it.keyPairBuilder().build()
            assertNotNull pair.public
            assertTrue pair.public instanceof RSAPublicKey
            assertEquals it.preferredKeyBitLength, pair.public.modulus.bitLength()
            assertTrue pair.private instanceof RSAPrivateKey
            assertEquals it.preferredKeyBitLength, pair.private.modulus.bitLength()
        }
    }

    @Test(expected = IllegalArgumentException)
    void testWeakPreferredKeyLength() {
        new DefaultRsaSignatureAlgorithm(256, 1024) //must be >= 2048
    }

    @Test
    void testValidateKeyWithoutRsaKey() {
        def key = createMock(PublicKey)
        replay key
        algs().each {
            it.validateKey(key, false)
            //no exception - can't check for RSAKey fields (e.g. PKCS11 or HSM key)
        }
        verify key
    }

    @Test
    void testValidateSigningKeyNotPrivate() {
        RSAPublicKey key = createMock(RSAPublicKey)
        def request = new DefaultSignatureRequest(new byte[1], null, null, key)
        try {
            SignatureAlgorithms.RS256.sign(request)
        } catch (InvalidKeyException e) {
            assertTrue e.getMessage().startsWith("Asymmetric key signatures must be created with PrivateKeys. The specified key is of type: ")
        }
    }

    @Test
    void testValidateSigningKeyWeakKey() {
        def gen = KeyPairGenerator.getInstance("RSA")
        gen.initialize(1024) //too week for any JWA RSA algorithm
        def pair = gen.generateKeyPair()

        def request = new DefaultSignatureRequest(new byte[1], null, null, pair.getPrivate())
        SignatureAlgorithms.values().findAll({ it.id.startsWith('RS') || it.id.startsWith('PS') }).each {
            try {
                it.sign(request)
            } catch (WeakKeyException expected) {
            }
        }
    }
}
