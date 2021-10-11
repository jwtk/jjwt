package io.jsonwebtoken.impl.security

import io.jsonwebtoken.impl.lang.CheckedFunction
import io.jsonwebtoken.security.CryptoException
import io.jsonwebtoken.security.SignatureException
import org.junit.Test

import javax.crypto.Cipher
import javax.crypto.Mac
import java.security.Provider
import java.security.Security
import java.security.Signature

import static org.junit.Assert.*

class JcaTemplateTest {

    @Test
    void testNewCipherWithExplicitProvider() {
        Provider provider = Security.getProvider('SunJCE')
        def template = new JcaTemplate('AES/CBC/PKCS5Padding', provider)
        template.execute(Cipher.class, new CheckedFunction<Cipher, byte[]>() {
            @Override
            byte[] apply(Cipher cipher) throws Exception {
                assertNotNull cipher
                assertSame provider, cipher.provider
                return new byte[0]
            }
        })
    }

    @Test
    void testGetInstanceFailureWithExplicitProvider() {
        //noinspection GroovyUnusedAssignment
        Provider provider = Security.getProvider('SunJCE')
        def supplier = new JcaTemplate.JcaInstanceSupplier<Cipher>(Cipher.class, "AES", provider) {
            @Override
            protected Cipher doGetInstance() {
                throw new IllegalStateException("foo")
            }
        }

        try {
            supplier.getInstance()
        } catch (CryptoException ce) { //should be wrapped as crypto exception
            String msg = ce.getMessage()
            //we check for starts-with/ends-with logic here instead of equals because the JCE provider String value
            //contains the JCE version number, and that can differ across JDK versions.  Since we use different JDK
            //versions in the test machine matrix, we don't want test failures from JDKs that run on higher versions
            assertTrue msg.startsWith('Unable to obtain Cipher instance from specified Provider {SunJCE')
            assertTrue msg.endsWith('} for JCA algorithm \'AES\': foo')
        }
    }

    @Test
    void testGetInstanceDoesNotWrapCryptoExceptions() {
        def ex = new CryptoException("foo")
        def supplier = new JcaTemplate.JcaInstanceSupplier<Cipher>(Cipher.class, 'AES', null) {
            @Override
            protected Cipher doGetInstance() {
                throw ex
            }
        }

        try {
            supplier.getInstance()
        } catch (CryptoException ce) {
            assertSame ex, ce
        }
    }

    static void wrapInSignatureException(Class instanceType, String jcaName) {
        def ex = new IllegalArgumentException("foo")
        def supplier = new JcaTemplate.JcaInstanceSupplier<Object>(instanceType, jcaName, null) {
            @Override
            protected Object doGetInstance() {
                throw ex
            }
        }

        try {
            supplier.getInstance()
        } catch (SignatureException se) {
            assertSame ex, se.getCause()
            String msg = "Unable to obtain ${instanceType.simpleName} instance from default JCA Provider for JCA algorithm '${jcaName}': foo"
            assertEquals msg, se.getMessage()
        }
    }

    @Test
    void testNonCryptoExceptionForSignatureOrMacInstanceIsWrappedInSignatureException() {
        wrapInSignatureException(Signature.class, 'RSA')
        wrapInSignatureException(Mac.class, 'HmacSHA256')
    }

    @Test
    void testCallbackThrowsException() {
        def ex = new Exception("testing")
        def template = new JcaTemplate('AES/CBC/PKCS5Padding', null)
        try {
            template.execute(Cipher.class, new CheckedFunction<Cipher, byte[]>() {
                @Override
                byte[] apply(Cipher cipher) throws Exception {
                    throw ex
                }
            })
        } catch (CryptoException e) {
            assertEquals 'Cipher callback execution failed: testing', e.getMessage()
            assertSame ex, e.getCause()
        }
    }

}
