package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.InvalidKeyException
import io.jsonwebtoken.security.SignatureAlgorithms
import io.jsonwebtoken.security.WeakKeyException
import org.junit.Test

import javax.crypto.spec.SecretKeySpec
import java.security.InvalidParameterException
import java.security.Key
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.NoSuchAlgorithmException
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

import static org.easymock.EasyMock.createMock
import static org.junit.Assert.*

class RsaSignatureAlgorithmTest {

    @Test
    void testGenerateKeyPair() {
        SignatureAlgorithms.values().findAll({it.name.startsWith("RS") || it.name.startsWith("PS")}).each {
            KeyPair pair = it.generateKeyPair()
            assertNotNull pair.public
            assertTrue pair.public instanceof RSAPublicKey
            assertEquals it.preferredKeyLength, pair.public.modulus.bitLength()
            assertTrue pair.private instanceof RSAPrivateKey
            assertEquals it.preferredKeyLength, pair.private.modulus.bitLength()
        }
    }

    @Test(expected = IllegalStateException)
    void testGenerateKeyGeneratorException() {
        def src = SignatureAlgorithms.RS256
        def alg = new RsaSignatureAlgorithm(src.name, src.jcaName, src.preferredKeyLength) {
            @Override
            protected KeyPairGenerator getKeyPairGenerator() throws NoSuchAlgorithmException, InvalidParameterException {
                throw new NoSuchAlgorithmException("testing")
            }
        }
        alg.generateKeyPair()
    }

    @Test(expected = IllegalArgumentException)
    void testWeakPreferredKeyLength() {
        new RsaSignatureAlgorithm('RS256', 'SHA256withRSA', 1024) //must be >= 2048
    }

    @Test
    void testValidateKeyRsaKey() {
        def request = new DefaultCryptoRequest<byte[], Key>(new byte[1], new SecretKeySpec(new byte[1], 'foo'), null, null)
        try {
            SignatureAlgorithms.RS256.sign(request)
        } catch (InvalidKeyException e) {
            assertTrue e.getMessage().contains("must be an RSAKey")
        }
    }

    @Test
    void testValidateSigningKeyNotPrivate() {
        RSAPublicKey key = createMock(RSAPublicKey)
        def request = new DefaultCryptoRequest<byte[], Key>(new byte[1], key, null, null)
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

        def request = new DefaultCryptoRequest<byte[], Key>(new byte[1], pair.getPrivate(), null, null)
        SignatureAlgorithms.values().findAll({it.name.startsWith('RS') || it.name.startsWith('PS')}).each {
            try {
                it.sign(request)
            } catch (WeakKeyException expected) {
            }
        }
    }
}
