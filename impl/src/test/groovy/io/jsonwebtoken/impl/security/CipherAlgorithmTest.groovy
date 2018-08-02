package io.jsonwebtoken.impl.security

import org.junit.Test

import javax.crypto.spec.SecretKeySpec
import java.security.Provider

import static org.easymock.EasyMock.createMock
import static org.junit.Assert.*

class CipherAlgorithmTest {

    @Test
    void testNewCipherTemplateNullRequest() {
        def alg = new TestCipherAlgorithm()
        def template = alg.newCipherTemplate(null)
        assertNull template.provider
        assertEquals 'AES/CBC/PKCS5Padding', template.transformation
    }

    @Test
    void testNewCipherTemplate() {

        byte[] data = new byte[32]
        Randoms.secureRandom().nextBytes(data)
        byte[] keyBytes = new byte[32]
        Randoms.secureRandom().nextBytes(keyBytes)
        def key = new SecretKeySpec(keyBytes, 'AES')

        def alg = new TestCipherAlgorithm()
        def template = alg.newCipherTemplate(new DefaultCryptoRequest(data, key, null, null))
        assertNull template.provider
        assertEquals 'AES/CBC/PKCS5Padding', template.transformation
    }

    @Test
    void testNewCipherTemplateWithProvider() {

        Provider provider = createMock(Provider)
        byte[] data = new byte[32]
        Randoms.secureRandom().nextBytes(data)
        byte[] keyBytes = new byte[32]
        Randoms.secureRandom().nextBytes(keyBytes)
        def key = new SecretKeySpec(keyBytes, 'AES')

        def alg = new TestCipherAlgorithm()
        def template = alg.newCipherTemplate(new DefaultCryptoRequest(data, key, provider, null))
        assertSame provider, template.provider
        assertEquals 'AES/CBC/PKCS5Padding', template.transformation
    }

    static class TestCipherAlgorithm extends CipherAlgorithm {
        def TestCipherAlgorithm() {
            super('AES', 'AES/CBC/PKCS5Padding')
        }
    }
}
