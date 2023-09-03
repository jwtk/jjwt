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

import io.jsonwebtoken.impl.lang.Bytes
import io.jsonwebtoken.impl.lang.CheckedFunction
import io.jsonwebtoken.lang.Classes
import io.jsonwebtoken.security.SecurityException
import io.jsonwebtoken.security.SignatureException
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Test

import javax.crypto.Cipher
import javax.crypto.Mac
import java.security.*
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.InvalidKeySpecException
import java.security.spec.KeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

import static org.junit.Assert.*

class JcaTemplateTest {

    static final Provider SUN_PROVIDER = Security.getProvider('SunJCE')
    static final Provider BC_PROVIDER = new BouncyCastleProvider()

    @Test
    void testGetInstanceExceptionMessage() {
        def factories = JcaTemplate.FACTORIES
        for (def factory : factories) {
            def clazz = factory.getInstanceClass()
            try {
                factory.get('foo', null)
            } catch (SecurityException expected) {
                if (clazz == Signature || clazz == Mac) {
                    assertTrue expected instanceof SignatureException
                }
                String prefix = "Unable to obtain 'foo' ${clazz.getSimpleName()} instance " +
                        "from default JCA Provider: "
                assertTrue expected.getMessage().startsWith(prefix)
            }
        }
    }

    @Test
    void testGetInstanceWithExplicitProviderExceptionMessage() {
        def factories = JcaTemplate.FACTORIES
        def provider = BC_PROVIDER
        for (def factory : factories) {
            def clazz = factory.getInstanceClass()
            try {
                factory.get('foo', provider)
            } catch (SecurityException expected) {
                if (clazz == Signature || clazz == Mac) {
                    assertTrue expected instanceof SignatureException
                }
                String prefix = "Unable to obtain 'foo' ${clazz.getSimpleName()} instance " +
                        "from specified '${provider.toString()}' Provider: "
                assertTrue expected.getMessage().startsWith(prefix)
            }
        }
    }

    @Test
    void testCallbackThrowsSecurityException() {
        // tests that any callback that throws a SecurityException doesn't need to be wrapped
        String msg = 'fubar'
        def template = new JcaTemplate('AES/CBC/PKCS5Padding')
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

    @Test
    void testInstanceFactoryFallbackFailureRetainsOriginalException() {
        String alg = 'foo'
        NoSuchAlgorithmException ex = new NoSuchAlgorithmException('foo')
        def factory = new JcaTemplate.JcaInstanceFactory<Cipher>(Cipher.class) {
            @Override
            protected Cipher doGet(String jcaName, Provider provider) throws Exception {
                throw ex
            }

            @Override
            protected Provider findBouncyCastle() {
                return null
            }
        }

        try {
            factory.get(alg, null)
            fail()
        } catch (SecurityException se) {
            assertSame ex, se.getCause()
            String msg = "Unable to obtain '$alg' Cipher instance from default JCA Provider: $alg"
            assertEquals msg, se.getMessage()
        }
    }

    @Test
    void testWrapWithDefaultJcaProviderAndFallbackProvider() {
        JcaTemplate.FACTORIES.each {
            Provider fallback = TestKeys.BC
            String jcaName = 'foo'
            NoSuchAlgorithmException nsa = new NoSuchAlgorithmException("doesn't exist")
            Exception out = ((JcaTemplate.JcaInstanceFactory) it).wrap(nsa, jcaName, null, fallback)
            assertTrue out instanceof SecurityException
            String msg = "Unable to obtain '${jcaName}' ${it.getId()} instance from default JCA Provider or fallback " +
                    "'${fallback.toString()}' Provider: doesn't exist"
            assertEquals msg, out.getMessage()
        }
    }

    @Test
    void testFallbackWithBouncyCastle() {
        def template = new JcaTemplate('foo')
        try {
            template.generateX509Certificate(Bytes.random(32))
        } catch (SecurityException expected) {
            String prefix = "Unable to obtain 'foo' CertificateFactory instance from default JCA Provider: "
            assertTrue expected.getMessage().startsWith(prefix)
            assertTrue expected.getCause() instanceof CertificateException
        }
    }

    @Test
    void testFallbackWithoutBouncyCastle() {
        def template = new JcaTemplate('foo') {
            @Override
            protected Provider findBouncyCastle() {
                return null
            }
        }
        try {
            template.generateX509Certificate(Bytes.random(32))
        } catch (SecurityException expected) {
            String prefix = "Unable to obtain 'foo' CertificateFactory instance from default JCA Provider: "
            assertTrue expected.getMessage().startsWith(prefix)
            assertTrue expected.getCause() instanceof CertificateException
        }
    }

    static InvalidKeySpecException jdk8213363BugEx(String msg) {
        // mock up JDK 11 bug behavior:
        String className = 'sun.security.ec.XDHKeyFactory'
        String methodName = 'engineGeneratePrivate'
        def ste = new StackTraceElement(className, methodName, null, 0)
        StackTraceElement[] stes = new StackTraceElement[1]
        stes[0] = ste
        def cause = new InvalidKeyException(msg)
        def ex = new InvalidKeySpecException(cause) {
            @Override
            StackTraceElement[] getStackTrace() {
                return stes
            }
        }
        return ex
    }

    @Test
    void testJdk8213363Bug() {
        for (def bundle in [TestKeys.X25519, TestKeys.X448]) {
            def privateKey = bundle.pair.private
            byte[] d = bundle.alg.getKeyMaterial(privateKey)
            byte[] prefix = new byte[2]; prefix[0] = (byte) 0x04; prefix[1] = (byte) d.length
            byte[] pkcs8d = Bytes.concat(prefix, d)
            int callCount = 0
            def ex = jdk8213363BugEx("key length must be ${d.length}")
            def template = new Jdk8213363JcaTemplate(bundle.alg.id) {
                @Override
                protected PrivateKey generatePrivate(KeyFactory factory, KeySpec spec) throws InvalidKeySpecException {
                    if (callCount == 0) { // simulate first attempt throwing an exception
                        callCount++
                        throw ex
                    }
                    // otherwise 2nd call due to fallback logic, simulate a successful call:
                    return privateKey
                }
            }
            assertSame privateKey, template.generatePrivate(new PKCS8EncodedKeySpec(pkcs8d))
        }
    }

    @Test
    void testGeneratePrivateRespecWithoutPkcs8() {
        byte[] invalid = Bytes.random(456)
        def template = new JcaTemplate('X448')
        try {
            template.generatePrivate(new X509EncodedKeySpec(invalid))
            fail()
        } catch (SecurityException expected) {
            boolean jdk11OrLater = Classes.isAvailable('java.security.interfaces.XECPrivateKey')
            String msg = 'KeyFactory callback execution failed: key spec not recognized'
            if (jdk11OrLater) {
                msg = 'KeyFactory callback execution failed: Only PKCS8EncodedKeySpec and XECPrivateKeySpec supported'
            }
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testGeneratePrivateRespecTooSmall() {
        byte[] invalid = Bytes.random(16)
        def ex = jdk8213363BugEx("key length must be ${invalid.length}")
        def template = new Jdk8213363JcaTemplate('X25519') {
            @Override
            protected PrivateKey generatePrivate(KeyFactory factory, KeySpec spec) throws InvalidKeySpecException {
                throw ex
            }
        }
        try {
            template.generatePrivate(new PKCS8EncodedKeySpec(invalid))
            fail()
        } catch (SecurityException expected) {
            String msg = "KeyFactory callback execution failed: java.security.InvalidKeyException: " +
                    "key length must be ${invalid.length}"
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testGeneratePrivateRespecTooLarge() {
        byte[] invalid = Bytes.random(50)
        def ex = jdk8213363BugEx("key length must be ${invalid.length}")
        def template = new Jdk8213363JcaTemplate('X448') {
            @Override
            protected PrivateKey generatePrivate(KeyFactory factory, KeySpec spec) throws InvalidKeySpecException {
                throw ex
            }
        }
        try {
            template.generatePrivate(new PKCS8EncodedKeySpec(invalid))
            fail()
        } catch (SecurityException expected) {
            String msg = "KeyFactory callback execution failed: java.security.InvalidKeyException: " +
                    "key length must be ${invalid.length}"
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testGetJdk8213363BugExpectedSizeNoExMsg() {
        InvalidKeyException ex = new InvalidKeyException()
        def template = new JcaTemplate('X448')
        assertEquals(-1, template.getJdk8213363BugExpectedSize(ex))
    }

    @Test
    void testGetJdk8213363BugExpectedSizeExMsgDoesntMatch() {
        InvalidKeyException ex = new InvalidKeyException('not what is expected')
        def template = new JcaTemplate('X448')
        assertEquals(-1, template.getJdk8213363BugExpectedSize(ex))
    }

    @Test
    void testGetJdk8213363BugExpectedSizeExMsgDoesntContainNumber() {
        InvalidKeyException ex = new InvalidKeyException('key length must be foo')
        def template = new JcaTemplate('X448')
        assertEquals(-1, template.getJdk8213363BugExpectedSize(ex))
    }

    @Test
    void testRespecIfNecessaryWithoutPkcs8KeySpec() {
        def spec = new X509EncodedKeySpec(Bytes.random(32))
        def template = new JcaTemplate('X448')
        assertNull template.respecIfNecessary(null, spec)
    }

    @Test
    void testRespecIfNecessaryNotJdk8213363Bug() {
        def ex = new InvalidKeySpecException('foo')
        def template = new JcaTemplate('X448')
        assertNull template.respecIfNecessary(ex, new PKCS8EncodedKeySpec(Bytes.random(32)))
    }

    @Test
    void testIsJdk11() {
        // determine which JDK the test is being run on in CI:
        boolean testMachineIsJdk11 = System.getProperty('java.version').startsWith('11')
        def template = new JcaTemplate('X448')
        if (testMachineIsJdk11) {
            assertTrue template.isJdk11()
        } else {
            assertFalse template.isJdk11()
        }
    }

    @Test
    void testCallbackThrowsException() {
        def ex = new Exception("testing")
        def template = new JcaTemplate('AES/CBC/PKCS5Padding')
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

    @Test
    void testWithCertificateFactory() {
        def template = new JcaTemplate('X.509')
        X509Certificate expected = TestKeys.RS256.cert
        X509Certificate cert = template.withCertificateFactory(new CheckedFunction<CertificateFactory, X509Certificate>() {
            @Override
            X509Certificate apply(CertificateFactory certificateFactory) throws Exception {
                (X509Certificate)certificateFactory.generateCertificate(new ByteArrayInputStream(expected.getEncoded()))
            }
        })
        assertEquals expected, cert
    }

    private static class Jdk8213363JcaTemplate extends JcaTemplate {
        Jdk8213363JcaTemplate(String jcaName) {
            super(jcaName)
        }

        @Override
        protected boolean isJdk11() {
            return true
        }
    }
}
