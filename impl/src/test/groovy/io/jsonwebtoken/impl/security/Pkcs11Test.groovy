/*
 * Copyright © 2023 jsonwebtoken.io
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
import io.jsonwebtoken.lang.Assert
import io.jsonwebtoken.lang.Classes
import io.jsonwebtoken.lang.Strings
import io.jsonwebtoken.security.*
import org.junit.Test

import java.security.KeyStore
import java.security.PrivateKey
import java.security.Provider
import java.security.Security
import java.security.cert.X509Certificate

import static org.junit.Assert.assertEquals

class Pkcs11Test {

    static final String PKCS11_LIB_ENV_VAR_NAME = 'JJWT_TEST_PKCS11_LIBRARY'
    static final List<String> DEFAULT_PKCS11_LIB_LOCATIONS = [
            // Tried in order:
            '/opt/homebrew/lib/softhsm/libsofthsm2.so', // macos: brew install softhsm
            '/usr/lib/softhsm/libsofthsm2.so',          // ubuntu: sudo apt-get install -y softhsm2
            '/usr/local/lib/libsofthsm2.so',            // other *nixes?
            'C:\\SoftHSM2\\lib\\softhsm2-x64.dll',      // https://github.com/disig/SoftHSM2-for-Windows
            'C:\\SoftHSM2\\lib\\softhsm2.dll'           // https://github.com/disig/SoftHSM2-for-Windows
    ]

    private static PrivateKey getKey(KeyStore ks, Identifiable alg, char[] pin) {
        // The SunPKCS11 KeyStore does not support Edwards Curve keys at all:
        if (alg instanceof EdwardsCurve) return null
        return ks.getKey(alg.id, pin) as PrivateKey
    }

    @SuppressWarnings(['GroovyAssignabilityCheck', 'UnnecessaryQualifiedReference'])
    private static Provider getAvailablePkcs11Provider() {
        String val = Strings.clean(System.getenv(PKCS11_LIB_ENV_VAR_NAME))
        def paths = []
        if (val != null) {
            paths.add(val) // highest priority
        }
        paths.addAll(DEFAULT_PKCS11_LIB_LOCATIONS) // remaining priorities
        File file = null
        for (String path : paths) {
            file = new File(path)
            if (!file.exists()) { // relative path? try to resolve canonical/absolute:
                URL url = Classes.getResource(path)
                file = url != null ? new File(url.toURI()) : null
            }
            if (file?.exists()) {
                file = file.getCanonicalFile()
                break
            }
        }
        Provider provider = null
        if (file) { // found the lib file, reference it via inline config:
            String config = """--
            name = jjwt
            library = ${file.getCanonicalPath()}
            attributes = compatibility
            """
            if (Provider.metaClass.respondsTo(Provider, 'configure', String)) { // JDK 9 or later
                provider = Security.getProvider("SunPKCS11")
                provider = provider.configure(config) as Provider
            } else { // JDK 8 or earlier:
                provider = new sun.security.pkcs11.SunPKCS11(config)
            }
        }
        return provider
    }

    private static Map<String, TestKeys.Bundle> findPkcs11Bundles(Provider provider) {

        if (provider == null) {
            return Collections.emptyMap()
        }

        Map<String, TestKeys.Bundle> bundles = new LinkedHashMap()

        KeyStore ks = KeyStore.getInstance("PKCS11", provider)
        //This pin equals the SoftHSM --so-pin and --pin values used in impl/src/test/scripts/softhsm:
        char[] pin = "1234".toCharArray()
        try {
            ks.load(null, pin)
        } catch (Throwable ignored) { // JVM can't support the keys or certs in SoftHSM
            return Collections.emptyMap()
        }

        def algs = []
        algs.addAll(Jwts.SIG.get().values().findAll({
            it instanceof KeyPairBuilderSupplier && it.id != 'EdDSA'
        }))
        algs.addAll(Jwks.CRV.get().values().findAll({ it instanceof EdwardsCurve }))

        for (Identifiable alg : algs) {
            def priv = getKey(ks, alg, pin)
            def cert = ks.getCertificate(alg.id) as X509Certificate
            // cert will be null for any PS* algs since  SoftHSM2 doesn't support them yet:
            // https://github.com/opendnssec/SoftHSMv2/issues/721
            def pub = cert?.getPublicKey()
            def bundle = new TestKeys.Bundle(alg, pub, priv, cert)
            bundles.put(alg.id, bundle)
        }

        return Collections.<String, TestKeys.Bundle> unmodifiableMap(bundles)
    }

    static Provider PKCS11 = getAvailablePkcs11Provider()

    /**
     * Maintainers note:
     *
     * This collection will only contain relevant entries when the following are true:
     *
     * 1. We're running on a machine that has an expected SoftHSM installation populated with entries
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
    static final Map<String, TestKeys.Bundle> PKCS11_BUNDLES = findPkcs11Bundles(PKCS11)

    static TestKeys.Bundle findPkcs11(Identifiable alg) {
        return PKCS11_BUNDLES.get(alg.getId())
    }

    static def ASYM = []
    static {
        ASYM.addAll(Jwts.SIG.get().values().findAll({
            it instanceof SignatureAlgorithm && it != Jwts.SIG.EdDSA
        })) // EdDSA accounted for by next two:
        ASYM.add(Jwks.CRV.Ed25519)
        ASYM.add(Jwks.CRV.Ed448)
    }

    static java.security.KeyPair findPkcs11Pair(Identifiable alg) {
        return findPkcs11(alg as Identifiable)?.pair
    }

    @Test
    void testJws() {
        def algs = ASYM
        algs.each { it ->

            java.security.KeyPair pair = findPkcs11Pair(it as Identifiable)

            if (pair?.private) { // Either the SunPKCS11 provider or SoftHSM2 supports the key algorithm

                SignatureAlgorithm alg = it instanceof Curve ? Jwts.SIG.EdDSA : it as SignatureAlgorithm

                // We need to specify the PKCS11 provider since we can't access the private key material:
                def jws = Jwts.builder().provider(PKCS11).issuer('me').signWith(pair.private, alg).compact()

                // Do not specify the PKCS11 provider (a JWS recipient doesn't have our HSM anyway):
                String iss = Jwts.parser().verifyWith(pair.public).build().parseClaimsJws(jws).getPayload().getIssuer()

                assertEquals 'me', iss
            }
        }
    }

    // create a jwe and then decrypt it
    static void encRoundtrip(TestKeys.Bundle bundle, def keyalg) {
        def pair = bundle.pair
        def pub = pair.public
        if (pub.getAlgorithm().startsWith(EdwardsCurve.OID_PREFIX)) {
            // If < JDK 11, the PKCS11 KeyStore doesn't understand X25519 and X448 algorithms, and just returns
            // a generic X509Key from the X.509 certificate, but that can't be used for encryption.  So we'll
            // use BouncyCastle to try and load the public key that way.  This is ok for testing because the
            // public key doesn't need to be a PKCS11 key since public key material is already available.
            // Decryption does need to use a PKCS11 key however since that is what allows us to assert
            // a valid test
            def cert = new JcaTemplate("X.509", TestKeys.BC).generateX509Certificate(bundle.cert.getEncoded())
            bundle.cert = cert
            bundle.chain = [cert]
            bundle.pair = new java.security.KeyPair(cert.getPublicKey(), bundle.pair.private)
            pub = bundle.pair.public
        }
        def priv = pair.private != null ? Keys.wrap(pair.private, pub) : null

        // Encryption uses the public key, and that key material is available, so no need for the PKCS11 provider:
        String jwe = Jwts.builder().issuer('me').encryptWith(pub, keyalg, Jwts.ENC.A256GCM).compact()

        // The private key can be null if SunPKCS11 doesn't support the key algorithm directly.  In this case
        // encryption only worked because generic X.509 decoding (from the key certificate in the keystore) produced the
        // public key.  So we can only decrypt if SunPKCS11 supports the private key, so check for non-null:
        if (priv) {
            // Decryption needs the private key, and that is inside the HSM, so the PKCS11 provider is required:
            String iss = Jwts.parser().provider(PKCS11).decryptWith(priv).build().parseClaimsJwe(jwe).getPayload().getIssuer()
            assertEquals 'me', iss
        }
    }

    @Test
    void testJwe() {

        def algs = []
        algs.addAll(Jwts.SIG.get().values().findAll({
            it.id.startsWith('RS') || it.id.startsWith('ES')
            // unfortunately we can't also match .startsWith('PS') because SoftHSM2 doesn't support RSA-PSS keys :(
            // see https://github.com/opendnssec/SoftHSMv2/issues/721
        }))
        // For Edwards key agreement, we can look up the public key via the X.509 cert, but SunPKCS11 doesn't
        // support reading the private keys :(
        // With the public key, we can at least encrypt, but we won't be able to decrypt since that needs the private key
        algs.add(Jwks.CRV.X25519)
        algs.add(Jwks.CRV.X448)

        algs.each {

            def bundle = findPkcs11(it as Identifiable) // bundle will be null with PSS* algs

            if (bundle?.pair?.public) { // null on JDK 13 w/ X25519 and X448
                String name = Assert.hasText(bundle.pair.public.algorithm, "PublicKey algorithm cannot be null/empty")
                if (name == 'RSA') {
                    // SunPKCS11 doesn't support RSA-OAEP* ciphers :(
                    // So we can only try with RSA1_5 and we have to skip RSA_OAEP and RSA_OAEP_256:
                    encRoundtrip(bundle, Jwts.KEY.RSA1_5)
                } else if (StandardCurves.findByKey(bundle.pair.public) != null) { // EC or Ed key
                    // try all ECDH key algorithms:
                    Jwts.KEY.get().values().findAll({ it.id.startsWith('ECDH-ES') }).each {
                        encRoundtrip(bundle, it)
                    }
                } else {
                    throw new IllegalStateException("Unexpected key algorithm: $name")
                }
            }
        }
    }
}
