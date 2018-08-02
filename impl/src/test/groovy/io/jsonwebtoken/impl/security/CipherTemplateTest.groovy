package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.CryptoException
import org.junit.Test

import javax.crypto.Cipher
import javax.crypto.NoSuchPaddingException
import java.security.NoSuchAlgorithmException
import java.security.Provider
import java.security.Security

import static org.junit.Assert.*

class CipherTemplateTest {

    @Test
    void testNewCipherWithExplicitProvider() {
        Provider provider = Security.getProvider('SunJCE')
        def template = new CipherTemplate('AES/CBC/PKCS5Padding', provider)
        template.execute(new CipherCallback<byte[]>() {
            @Override
            byte[] doWithCipher(Cipher cipher) throws Exception {
                assertNotNull cipher
                assertSame provider, cipher.provider
            }
        })
    }

    @Test
    void testNewCipherFailedWithDefaultProvider() {
        def ex = new IllegalStateException('testing')
        def template = new CipherTemplate('AES/CBC/PKCS5Padding', null) {
            @Override
            Cipher getCipherInstance(String transformation, Provider provider) throws NoSuchPaddingException, NoSuchAlgorithmException {
                throw ex
            }
        }

        try {
            template.execute(new CipherCallback<byte[]>() {
                @Override
                byte[] doWithCipher(Cipher cipher) throws Exception {
                    return null
                }
            })
        } catch (CryptoException expected) {
            assertEquals 'Unable to obtain cipher from default JCA Provider for transformation \'AES/CBC/PKCS5Padding\': testing', expected.getMessage()
            assertSame ex, expected.getCause()
        }
    }

    @Test
    void testNewCipherFailedWithExplicitProvider() {
        def ex = new IllegalStateException('testing')
        Provider provider = Security.getProvider('SunJCE')
        def template = new CipherTemplate('AES/CBC/PKCS5Padding', provider) {
            @Override
            Cipher getCipherInstance(String transformation, Provider p) throws NoSuchPaddingException, NoSuchAlgorithmException {
                throw ex
            }
        }

        try {
            template.execute(new CipherCallback<byte[]>() {
                @Override
                byte[] doWithCipher(Cipher cipher) throws Exception {
                    return null
                }
            })
        } catch (CryptoException expected) {
            assertTrue expected.getMessage().startsWith('Unable to obtain cipher from specified Provider {')
            assertTrue expected.getMessage().endsWith('} for transformation \'AES/CBC/PKCS5Padding\': testing')
            assertSame ex, expected.getCause()
        }
    }

    @Test
    void testCallbackThrowsException() {
        def ex = new Exception("testing")
        def template = new CipherTemplate('AES/CBC/PKCS5Padding', null)
        try {
            template.execute(new CipherCallback<byte[]>() {
                @Override
                byte[] doWithCipher(Cipher cipher) throws Exception {
                    throw ex
                }
            })
        } catch (CryptoException e) {
            assertEquals 'Cipher callback execution failed: testing', e.getMessage()
            assertSame ex, e.getCause()
        }
    }
}
