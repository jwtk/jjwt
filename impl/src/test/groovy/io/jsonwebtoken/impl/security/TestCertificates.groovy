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

import io.jsonwebtoken.Identifiable
import io.jsonwebtoken.impl.lang.Bytes
import io.jsonwebtoken.impl.lang.CheckedFunction
import io.jsonwebtoken.impl.lang.Conditions
import io.jsonwebtoken.lang.Assert
import io.jsonwebtoken.lang.Classes
import io.jsonwebtoken.lang.Strings
import io.jsonwebtoken.security.SignatureAlgorithm
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter

import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.Provider
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.X509EncodedKeySpec

/**
 * For test cases that need to read certificate and/or PEM files.  Encapsulates BouncyCastle API to
 * this class so it doesn't need to propagate across other test classes.
 *
 * MAINTAINERS NOTE:
 *
 * If this logic is ever needed in the impl or api modules, do not keep the
 * name of this class - it was quickly thrown together and it isn't appropriately named for exposure in a public
 * module.  Thought/design is necessary to see if/how cert/pem reading should be exposed in an easy-to-use and
 * maintain API (e.g. probably a builder).
 *
 * The only purpose of this class and its methods are to:
 *   1) be used in Test classes only, and
 *   2) encapsulate the BouncyCastle API so it is not exposed to other Test classes.
 */
class TestCertificates {

    private static Provider BC = Assert.notNull(Providers.findBouncyCastle(Conditions.TRUE),
            "BC must be available to test cases.")

    private static InputStream getResourceStream(String filename) {
        String packageName = TestCertificates.class.getPackage().getName()
        String resourcePath = Strings.replace(packageName, ".", "/") + "/" + filename
        return Classes.getResourceAsStream(resourcePath)
    }

    private static PEMParser getParser(String filename) {
        InputStream is = getResourceStream(filename)
        return new PEMParser(new BufferedReader(new InputStreamReader(is, StandardCharsets.ISO_8859_1)))
    }

    private static <T> T bcFallback(final Identifiable alg, Closure<T> closure) {
        Provider provider = alg.getProvider() as Provider // null on JVMs with native support for `alg`
        try {
            return closure.call(alg, provider)
        } catch (Throwable t) {

            // All test cert and key files were created with OpenSSL, so the only time this should happen is if the
            // JDK natively supports the alg, but has a bug that prevents it from reading the file correctly.  So
            // we account for those bugs here as indicators that we should retry with BC.

            // https://bugs.openjdk.org/browse/JDK-8242556
            // Oracle only backported this fix to JDK 8u271+, 11.0.9+, and 15+, so we'll need to fall back to
            // BC (which can read the files correctly) on JDK 9, 10, 12, 13, and 14.
            boolean jdk8242556Bug = alg instanceof SignatureAlgorithm && alg.getId().startsWith("PS") &&
                    t.message.contains('Unsupported algorithm 1.2.840.113549.1.1.10')

            // https://bugs.openjdk.org/browse/JDK-8213363) for X25519 and X448 encoded keys. JDK 11's
            // SunCE provider incorrectly expects an ASN.1 OCTET STRING (without the DER tag/length prefix)
            // when it should actually be a BER-encoded OCTET STRING (with the tag/length prefix).
            boolean jdk8213363Bug = alg instanceof EdwardsCurve && !((EdwardsCurve) alg).isSignatureCurve() &&
                    System.getProperty("java.version").startsWith("11")

            // Now assert that we're experiencing one of the expected bugs, because if not, we need to know about
            // it in test results and fix this implementation:
            if (!jdk8242556Bug && !jdk8213363Bug) {
                String msg = "Unable to read ${alg.getId()} file: ${t.message}"
                throw new IllegalStateException(msg, t)
            }

            // otherwise, we are indeed experiencing one of the expected bugs, so use BC as a backup:
            return closure.call(alg, BC)
        }
    }

    private static def readPublicKey = { Identifiable alg, Provider provider ->
        PEMParser parser = getParser(alg.id + '.pub.pem')
        parser.withCloseable {
            SubjectPublicKeyInfo info = parser.readObject() as SubjectPublicKeyInfo
            JcaTemplate template = new JcaTemplate(alg.getJcaName(), provider)
            template.withKeyFactory(new CheckedFunction<KeyFactory, PublicKey>() {
                @Override
                PublicKey apply(KeyFactory keyFactory) throws Exception {
                    return keyFactory.generatePublic(new X509EncodedKeySpec(info.getEncoded()))
                }
            })
        }
    }

    private static def readCert = { Identifiable alg, Provider provider ->
        InputStream is = getResourceStream(alg.id + '.crt.pem')
        is.withCloseable {
            JcaTemplate template = new JcaTemplate("X.509", provider)
            template.withCertificateFactory(new CheckedFunction<CertificateFactory, X509Certificate>() {
                @Override
                X509Certificate apply(CertificateFactory factory) throws Exception {
                    return (X509Certificate) factory.generateCertificate(it)
                }
            })
        }
    }

    private static def readPrivateKey = { Identifiable alg, Provider provider ->
        final String id = alg.id
        PEMParser parser = getParser(id + '.key.pem')
        parser.withCloseable {
            PrivateKeyInfo info
            Object object = parser.readObject()
            if (object instanceof PEMKeyPair) {
                info = ((PEMKeyPair) object).getPrivateKeyInfo()
            } else {
                info = (PrivateKeyInfo) object
            }
            def converter = new JcaPEMKeyConverter()
            if (provider != null) {
                converter.setProvider(provider)
            } else if (id.startsWith("X") && System.getProperty("java.version").startsWith("11")) {
                EdwardsCurve curve = EdwardsCurve.findById(id)
                Assert.notNull(curve, "Curve cannot be null.")
                int expectedByteLen = ((curve.keyBitLength + 7) / 8) as int
                // Address the [JDK 11 SunCE provider bug](https://bugs.openjdk.org/browse/JDK-8213363) for X25519
                // and X448 encoded keys: Even though the file is encoded properly (it was created by OpenSSL), JDK 11's
                // SunCE provider incorrectly expects an ASN.1 OCTET STRING (without the DER tag/length prefix)
                // when it should actually be a BER-encoded OCTET STRING (with the tag/length prefix).
                // So we get the raw bytes and use our key generator:
                byte[] keyOctets = info.getPrivateKey().getOctets()
                int lenDifference = Bytes.length(keyOctets) - expectedByteLen
                if (lenDifference > 0) {
                    byte[] derPrefixRemoved = new byte[expectedByteLen]
                    System.arraycopy(keyOctets, lenDifference, derPrefixRemoved, 0, expectedByteLen)
                    keyOctets = derPrefixRemoved
                }
                return curve.toPrivateKey(keyOctets, null)
            }
            return converter.getPrivateKey(info)
        }
    }

    static TestKeys.Bundle readBundle(EdwardsCurve curve) {
        //PublicKey pub = readTestPublicKey(curve)
        //PrivateKey priv = readTestPrivateKey(curve)
        PublicKey pub = bcFallback(curve, readPublicKey) as PublicKey
        PrivateKey priv = bcFallback(curve, readPrivateKey) as PrivateKey
        return new TestKeys.Bundle(pub, priv)
    }

    static TestKeys.Bundle readBundle(Identifiable alg) {
        //X509Certificate cert = readTestCertificate(alg)
        //PrivateKey priv = readTestPrivateKey(alg)
        X509Certificate cert = bcFallback(alg, readCert) as X509Certificate
        PrivateKey priv = bcFallback(alg, readPrivateKey) as PrivateKey
        return new TestKeys.Bundle(cert, priv)
    }
}
