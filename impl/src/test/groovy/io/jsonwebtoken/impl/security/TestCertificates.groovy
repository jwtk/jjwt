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
import io.jsonwebtoken.lang.Assert
import io.jsonwebtoken.lang.Classes
import io.jsonwebtoken.lang.Strings
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

    private static InputStream getResourceStream(String filename) {
        String packageName = TestCertificates.class.getPackage().getName()
        String resourcePath = Strings.replace(packageName, ".", "/") + "/" + filename
        return Classes.getResourceAsStream(resourcePath)
    }

    private static PEMParser getParser(String filename) {
        InputStream is = Classes.getResourceAsStream('io/jsonwebtoken/impl/security/' + filename)
        return new PEMParser(new BufferedReader(new InputStreamReader(is, StandardCharsets.ISO_8859_1)))
    }

    private static String getKeyFilePrefix(Identifiable alg) {
        if (alg instanceof EdSignatureAlgorithm) {
            return alg.preferredCurve.getId()
        }
        return alg.getId()
    }

    static X509Certificate readTestCertificate(Identifiable alg) {
        InputStream is = getResourceStream(getKeyFilePrefix(alg) + '.crt.pem')
        try {
            JcaTemplate template = new JcaTemplate("X.509", alg.getProvider())
            template.withCertificateFactory(new CheckedFunction<CertificateFactory, X509Certificate>() {
                @Override
                X509Certificate apply(CertificateFactory factory) throws Exception {
                    return (X509Certificate) factory.generateCertificate(is)
                }
            })
        } finally {
            is.close()
        }
    }

    static PublicKey readTestPublicKey(EdwardsCurve crv) {
        PEMParser parser = getParser(crv.getId() + '.pub.pem')
        try {
            SubjectPublicKeyInfo info = parser.readObject() as SubjectPublicKeyInfo
            def template = new JcaTemplate(crv.getJcaName(), crv.getProvider())
            return template.withKeyFactory(new CheckedFunction<KeyFactory, PublicKey>() {
                @Override
                PublicKey apply(KeyFactory keyFactory) throws Exception {
                    return keyFactory.generatePublic(new X509EncodedKeySpec(info.getEncoded()))
                }
            })
        } finally {
            parser.close()
        }
    }

    static PrivateKey readTestPrivateKey(Identifiable alg) {
        return readTestPrivateKey(getKeyFilePrefix(alg), alg.getProvider())
    }

    static PrivateKey readTestPrivateKey(String filenamePrefix, Provider provider) {
        PEMParser parser = getParser(filenamePrefix + '.key.pem')
        try {
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
            } else if (filenamePrefix.startsWith("X") && System.getProperty("java.version").startsWith("11")) {
                EdwardsCurve curve = EdwardsCurve.findById(filenamePrefix)
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
        } finally {
            parser.close()
        }
    }

    static TestKeys.Bundle readBundle(EdwardsCurve curve) {
        PublicKey pub = readTestPublicKey(curve)
        PrivateKey priv = readTestPrivateKey(curve)
        return new TestKeys.Bundle(pub, priv)
    }

    static TestKeys.Bundle readAsymmetricBundle(Identifiable alg) {
        X509Certificate cert = readTestCertificate(alg)
        PrivateKey priv = readTestPrivateKey(alg)
        return new TestKeys.Bundle(cert, priv)
    }
}
