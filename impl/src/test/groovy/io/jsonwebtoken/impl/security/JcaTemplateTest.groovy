/*
 * Copyright (C) 2020 jsonwebtoken.io
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

import io.jsonwebtoken.impl.lang.CheckedFunction
import io.jsonwebtoken.security.SecurityException
import io.jsonwebtoken.security.SignatureException
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Test

import javax.crypto.Cipher
import javax.crypto.Mac
import java.security.Provider
import java.security.Security
import java.security.Signature

import static org.junit.Assert.*

class JcaTemplateTest {

    static final Provider SUN_PROVIDER = Security.getProvider('SunJCE')
    static final Provider BC_PROVIDER = new BouncyCastleProvider()

    @Test
    void testGetInstanceExceptionMessage() {
        def factories = JcaTemplate.FACTORIES
        for(def factory : factories) {
            def clazz = factory.getInstanceClass()
            try {
                factory.get('foo', null)
            } catch (SecurityException expected) {
                if (clazz == Signature || clazz == Mac) {
                    assertTrue expected instanceof SignatureException
                }
                String prefix = "Unable to obtain ${clazz.getSimpleName()} instance " +
                        "from default JCA Provider for JCA algorithm 'foo': "
                assertTrue expected.getMessage().startsWith(prefix)
            }
        }
    }

    @Test
    void testGetInstanceWithExplicitProviderExceptionMessage() {
        def factories = JcaTemplate.FACTORIES
        def provider = BC_PROVIDER
        for(def factory : factories) {
            def clazz = factory.getInstanceClass()
            try {
                factory.get('foo', provider)
            } catch (SecurityException expected) {
                if (clazz == Signature || clazz == Mac) {
                    assertTrue expected instanceof SignatureException
                }
                String prefix = "Unable to obtain ${clazz.getSimpleName()} instance " +
                        "from specified Provider '${provider.toString()}' for JCA algorithm 'foo': "
                assertTrue expected.getMessage().startsWith(prefix)
            }
        }
    }

    @Test
    void testCallbackThrowsSecurityException() {
        // tests that any callback that throws a SecurityException doesn't need to be wrapped
        String msg = 'fubar'
        def template = new JcaTemplate('AES/CBC/PKCS5Padding', null)
        try {
            template.withCipher(new CheckedFunction<Cipher, byte[]>() {
                @Override
                byte[] apply(Cipher cipher) throws Exception {
                    throw new SecurityException(msg)
                }
            })
        } catch (SecurityException ex) {
            assertEquals msg, ex.getMessage()
        }
    }

    @Test
    void testNewCipherWithExplicitProvider() {
        Provider provider = SUN_PROVIDER
        def template = new JcaTemplate('AES/CBC/PKCS5Padding', provider)
        template.withCipher(new CheckedFunction<Cipher, byte[]>() {
            @Override
            byte[] apply(Cipher cipher) throws Exception {
                assertNotNull cipher
                assertSame provider, cipher.getProvider()
                return new byte[0]
            }
        })
    }

//    @Test
//    void testGetInstanceFailureWithExplicitProvider() {
//        //noinspection GroovyUnusedAssignment
//        Provider provider = Security.getProvider('SunJCE')
//        def supplier = new JcaTemplate.JcaInstanceSupplier<Cipher>(Cipher.class, "AES", provider) {
//            @Override
//            protected Cipher doGetInstance() {
//                throw new IllegalStateException("foo")
//            }
//        }
//
//        try {
//            supplier.getInstance()
//        } catch (SecurityException ce) { //should be wrapped as SecurityException
//            String msg = ce.getMessage()
//            //we check for starts-with/ends-with logic here instead of equals because the JCE provider String value
//            //contains the JCE version number, and that can differ across JDK versions.  Since we use different JDK
//            //versions in the test machine matrix, we don't want test failures from JDKs that run on higher versions
//            assertTrue msg.startsWith('Unable to obtain Cipher instance from specified Provider {SunJCE')
//            assertTrue msg.endsWith('} for JCA algorithm \'AES\': foo')
//        }
//    }
//
//    @Test
//    void testGetInstanceDoesNotWrapCryptoExceptions() {
//        def ex = new SecurityException("foo")
//        def supplier = new JcaTemplate.JcaInstanceSupplier<Cipher>(Cipher.class, 'AES', null) {
//            @Override
//            protected Cipher doGetInstance() {
//                throw ex
//            }
//        }
//
//        try {
//            supplier.getInstance()
//        } catch (SecurityException ce) {
//            assertSame ex, ce
//        }
//    }
//
//    static void wrapInSignatureException(Class instanceType, String jcaName) {
//        def ex = new IllegalArgumentException("foo")
//        def supplier = new JcaTemplate.JcaInstanceSupplier<Object>(instanceType, jcaName, null) {
//            @Override
//            protected Object doGetInstance() {
//                throw ex
//            }
//        }
//
//        try {
//            supplier.getInstance()
//        } catch (SignatureException se) {
//            assertSame ex, se.getCause()
//            String msg = "Unable to obtain ${instanceType.simpleName} instance from default JCA Provider for JCA algorithm '${jcaName}': foo"
//            assertEquals msg, se.getMessage()
//        }
//    }

//    @Test
//    void testNonCryptoExceptionForSignatureOrMacInstanceIsWrappedInSignatureException() {
//        wrapInSignatureException(Signature.class, 'RSA')
//        wrapInSignatureException(Mac.class, 'HmacSHA256')
//    }

    @Test
    void testCallbackThrowsException() {
        def ex = new Exception("testing")
        def template = new JcaTemplate('AES/CBC/PKCS5Padding', null)
        try {
            template.withCipher(new CheckedFunction<Cipher, byte[]>() {
                @Override
                byte[] apply(Cipher cipher) throws Exception {
                    throw ex
                }
            })
        } catch (SecurityException e) {
            assertEquals 'Cipher callback execution failed: testing', e.getMessage()
            assertSame ex, e.getCause()
        }
    }

}
