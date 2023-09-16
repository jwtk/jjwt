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
import io.jsonwebtoken.lang.Classes
import io.jsonwebtoken.lang.Strings
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser

import java.nio.charset.StandardCharsets
import java.security.PrivateKey
import java.security.Provider
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.security.spec.KeySpec
import java.security.spec.PKCS8EncodedKeySpec
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

    static Provider BC = new BouncyCastleProvider()

    private static String relativePath(String basename) {
        String packageName = TestCertificates.class.getPackage().getName()
        return Strings.replace(packageName, ".", "/") + "/" + basename
    }

    private static InputStream getResourceStream(String filename) {
        String resourcePath = relativePath(filename)
        return Classes.getResourceAsStream(resourcePath)
    }

    private static PEMParser getParser(String filename) {
        InputStream is = getResourceStream(filename)
        return new PEMParser(new BufferedReader(new InputStreamReader(is, StandardCharsets.ISO_8859_1)))
    }

    private static String keyJcaName(Identifiable alg) {
        String jcaName = alg.getId()
        if (jcaName.startsWith('ES')) {
            jcaName = 'EC'
        } else if (jcaName.startsWith('PS')) {
            jcaName = 'RSASSA-PSS'
        } else if (jcaName.startsWith('RS')) {
            jcaName = 'RSA'
        }
        return jcaName
    }

    private static PublicKey readPublicKey(Identifiable alg) {
        PEMParser parser = getParser(alg.id + '.pub.pem')
        parser.withCloseable {
            SubjectPublicKeyInfo info = it.readObject() as SubjectPublicKeyInfo
            JcaTemplate template = new JcaTemplate(keyJcaName(alg))
            return template.generatePublic(new X509EncodedKeySpec(info.getEncoded()))
        }
    }

    private static X509Certificate readCert(Identifiable alg, Provider provider) {
        InputStream is = getResourceStream(alg.id + '.crt.pem')
        JcaTemplate template = new JcaTemplate("X.509", provider)
        return template.generateX509Certificate(is.getBytes())
    }

    private static PrivateKey readPrivateKey(Identifiable alg) {
        final String id = alg.id
        PEMParser parser = getParser(id + '.pkcs8.pem')
        parser.withCloseable {
            PrivateKeyInfo info
            Object object = it.readObject()
            if (object instanceof PEMKeyPair) {
                info = ((PEMKeyPair) object).getPrivateKeyInfo()
            } else {
                info = (PrivateKeyInfo) object
            }
            final KeySpec spec = new PKCS8EncodedKeySpec(info.getEncoded())
            return new JcaTemplate(keyJcaName(alg), null).generatePrivate(spec)
        }
    }

    static TestKeys.Bundle readBundle(Identifiable alg) {

        PublicKey pub = readPublicKey(alg) as PublicKey
        PrivateKey priv = readPrivateKey(alg) as PrivateKey

        // If the public key loaded is a BC key, the default provider doesn't understand the cert key OID
        // (for example, an Ed25519 key on JDK 8 which doesn't natively support such keys). This means the
        // X.509 certificate should also be loaded by BC; otherwise the Sun X.509 CertificateFactory returns
        // a certificate with certificate.getPublicKey() being a sun X509Key instead of the type-specific key we want:
        Provider provider = null
        if (pub.getClass().getName().startsWith("org.bouncycastle")) {
            provider = BC
        }
        X509Certificate cert = readCert(alg, provider) as X509Certificate
        PublicKey certPub = cert.getPublicKey()
        assert pub.equals(certPub)

        return new TestKeys.Bundle(alg, pub, priv, cert)
    }
}
