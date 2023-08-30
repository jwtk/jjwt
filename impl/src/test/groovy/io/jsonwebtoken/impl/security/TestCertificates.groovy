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
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.lang.Classes
import io.jsonwebtoken.lang.Strings
import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.KeyPairBuilderSupplier
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser

import java.nio.charset.StandardCharsets
import java.security.*
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

    static Provider PKCS11 // currently null on windows. TODO: enable windows.pkcs11.cfg file

    private static <T> T jvmTry(Closure<T> c) {
        try {
            return c.call()
        } catch (Throwable t) {
            String msg = t.getMessage()
            if (msg?.contains("nsupported algorithm") || msg?.contains("nknown key type")) {
                // JVM version doesn't support a key or cert in the PKCS11 store and fails lookup,
                // so there's nothing we can do, just return null:
                return null
            }
            throw new IllegalStateException("Unexpected exception: " + msg, t)
        }
    }

    private static Collection<TestKeys.Bundle> findPkcs11Bundles(Provider provider) {

        Collection<TestKeys.Bundle> bundles = new ArrayList<>(20)

        KeyStore ks = KeyStore.getInstance("PKCS11", provider)
        //This pin equals the SoftHSM --so-pin and --pin values used in impl/src/test/scripts/softhsm:
        char[] pin = "1234".toCharArray()
        Boolean result = jvmTry { ks.load(null, pin); return Boolean.TRUE }
        if (result == null) return Collections.emptySet()

        def algs = []
        algs.addAll(Jwts.SIG.get().values().findAll({
            it instanceof KeyPairBuilderSupplier && it.id != 'EdDSA'
        }))
        algs.addAll(Jwks.CRV.get().values().findAll({ it instanceof EdwardsCurve }))

        for (Identifiable alg : algs) {
            def priv = jvmTry { ks.getKey(alg.id, pin) as PrivateKey }
            def cert = jvmTry { ks.getCertificate(alg.id) as X509Certificate }
            // cert will be null if the JVM doesn't support its algorithm or for any PS* algs since
            // SoftHSM2 doesn't support them yet (https://github.com/opendnssec/SoftHSMv2/issues/721):
            def pub = cert?.getPublicKey()
            def bundle = new TestKeys.Bundle(alg, pub, priv, cert)
            bundles.add(bundle)
        }

        return Collections.unmodifiableList(bundles) // empty on windows at the moment
    }

    /**
     * Maintainers note:
     *
     * This collection will only contain relevant entries when the following are true:
     *
     * 1. We're running on a Linux or MacOS machine that has an expected SoftHSM installation populated with entries
     *    via the impl/src/test/scripts/softhsm script in this git repository.
     *
     * 2. The current JVM version supports the key algorithm identified in the PKCS11 PrivateKey or X509Certificate.
     *    This means:
     *      - On JDK < 15, Ed25519 and Ed448 PrivateKeys cannot be loaded (but their certs and PublicKeys may be
     *        able to be loaded if/when Sun Provider implementation supports generic X509 encoding).
     *      - On JDK < 11 X25519 and X448 PrivateKeys cannot be loaded (but their certs and PublicKeys may be).
     *
     * 3. RSASSA-PSS keys of any kind are not available because SoftHSM doesn't currently support them. See
     *    https://github.com/opendnssec/SoftHSMv2/issues/721
     */
    static final Collection<TestKeys.Bundle> PKCS11_BUNDLES // empty on windows until windows.pkcs11.cfg can be used

    static {
        Collection<TestKeys.Bundle> bundles = Collections.emptySet() // default
        // false implies linux/ubuntu until we need to support Windows:
        String osname = System.getProperty('os.name').toLowerCase()
        String prefix = osname.startsWith('mac') ? 'macos' : (osname.startsWith("linux") ? 'linux' : null)
        if (prefix != null) { // null on windows at the moment
            String basename = "${prefix}.pkcs11.cfg"
            String relativePath = relativePath(basename)
            URL url = Classes.getResource(relativePath)
            File file = new File(url.toURI())
            String canonicalPath = file.getAbsolutePath()

            if (Provider.metaClass.respondsTo(Provider, 'configure', String)) { // JDK 9 or later
                Provider p = Security.getProvider("SunPKCS11")
                PKCS11 = p.configure(canonicalPath) as Provider
            } else { // JDK 8 or earlier:
                //noinspection UnnecessaryQualifiedReference
                PKCS11 = new sun.security.pkcs11.SunPKCS11(canonicalPath)
            }
            bundles = findPkcs11Bundles(PKCS11)
        }
        PKCS11_BUNDLES = bundles
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
            JcaTemplate template = new JcaTemplate(keyJcaName(alg), null)
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
