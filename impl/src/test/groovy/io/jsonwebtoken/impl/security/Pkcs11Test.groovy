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
import io.jsonwebtoken.impl.lang.Bytes
import io.jsonwebtoken.lang.Assert
import io.jsonwebtoken.lang.Classes
import io.jsonwebtoken.lang.Strings
import io.jsonwebtoken.security.*
import org.junit.Test

import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import java.security.*
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
    //This pin equals the SoftHSM --so-pin and --pin values used in impl/src/test/scripts/softhsm:
    static final char[] PIN = "1234".toCharArray()

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
            # Needed for JWT ECDH-ES* algorithms using SunPKCS11 KeyAgreement:
            # https://stackoverflow.com/questions/51663622/do-sunpkcs11-supports-ck-sensitive-attribute-for-derived-key-using-ecdh
            attributes(generate,CKO_SECRET_KEY,CKK_GENERIC_SECRET) = {
              CKA_SENSITIVE = false
              CKA_EXTRACTABLE = true
            }
            """
            if (Provider.metaClass.respondsTo(Provider, 'configure', String)) { // JDK 9 or later
                provider = Security.getProvider("SunPKCS11")
                provider = provider.configure(config) as Provider
            } else { // JDK 8 or earlier:
                try {
                    provider = new sun.security.pkcs11.SunPKCS11(config)
                } catch (Throwable ignored) { // MacOS on JDK 7: libsofthsm2.so is arm64, JDK is x86_64, can't load
                }
            }
        }
        return provider
    }

    private static KeyStore loadKeyStore(Provider provider) {
        if (provider == null) return null
        KeyStore ks = KeyStore.getInstance("PKCS11", provider)
        try {
            ks.load(null, PIN)
            return ks
        } catch (Throwable ignored) { // JVM can't support the keys or certs in SoftHSM
            return null
        }
    }

    private static Map<Identifiable, SecretKey> findPkcs11SecretKeys(KeyStore ks) {
        if (ks == null) return Collections.emptyMap()

        Map<Identifiable, SecretKey> keys = new LinkedHashMap()

        def prot = new KeyStore.PasswordProtection(PIN)

        def algs = [] as List<Identifiable>
        algs.addAll(Jwts.SIG.get().values().findAll({ it instanceof KeyBuilderSupplier }))
        algs.addAll(Jwts.ENC.get().values())

        algs.each { Identifiable alg ->
            // find any previous one:
            SecretKey key = ks.getKey(alg.id, PIN) as SecretKey
            if (key == null) { // didn't exist, lazily create it in SoftHSM:
                key = alg.key().build()
                if (alg instanceof HmacAesAeadAlgorithm) {
                    // PKCS11 provider doesn't like non-standard key lengths with the AES algorithm, so we'll
                    // 'trick' it by using HmacSHA*** alg identifier
                    def encoded = key.getEncoded()
                    long bitlen = Bytes.bitLength(encoded)
                    key = new SecretKeySpec(key.getEncoded(), "HmacSHA${bitlen}")
                }
                KeyStore.Entry entry = new KeyStore.SecretKeyEntry(key)
                ks.setEntry(alg.id, entry, prot)
                // it's saved now, but we need to look up the (restricted) PKCS11 representation to use that during
                // testing to more accurately reflect real/restricted HSM access:
                key = ks.getKey(alg.id, PIN) as SecretKey
            }
            keys.put(alg, key)
        }

        return keys
    }

    private static Map<String, TestKeys.Bundle> findPkcs11Bundles(KeyStore ks) {
        if (ks == null) return Collections.emptyMap()

        Map<String, TestKeys.Bundle> bundles = new LinkedHashMap()

        def algs = []
        algs.addAll(Jwts.SIG.get().values().findAll({
            it instanceof KeyPairBuilderSupplier && it.id != 'EdDSA'
        }))
        algs.addAll(Jwks.CRV.get().values().findAll({ it instanceof EdwardsCurve }))

        for (Identifiable alg : algs) {
            def priv = getKey(ks, alg, PIN)
            def cert = ks.getCertificate(alg.id) as X509Certificate
            // cert will be null for any PS* algs since  SoftHSM2 doesn't support them yet:
            // https://github.com/opendnssec/SoftHSMv2/issues/721
            def pub = cert?.getPublicKey()
            def bundle = new TestKeys.Bundle(alg, pub, priv, cert)
            bundles.put(alg.id, bundle)
        }

        return Collections.<String, TestKeys.Bundle> unmodifiableMap(bundles)
    }

    static final Provider PKCS11 = getAvailablePkcs11Provider()

    static final KeyStore KEYSTORE = loadKeyStore(PKCS11)

    static final Map<Identifiable, SecretKey> PKCS11_SECRETKEYS = findPkcs11SecretKeys(KEYSTORE)

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
     *    https://github.com/opendnssec/SoftHSMv2/issues/721*/
    static final Map<String, TestKeys.Bundle> PKCS11_BUNDLES = findPkcs11Bundles(KEYSTORE)

    static TestKeys.Bundle findPkcs11(Identifiable alg) {
        return PKCS11_BUNDLES.get(alg.getId())
    }

    static SecretKey findPkcs11SecretKey(Identifiable alg) {
        return PKCS11_SECRETKEYS.get(alg)
    }

    static java.security.KeyPair findPkcs11Pair(Identifiable alg) {
        return findPkcs11(alg as Identifiable)?.pair
    }

    /**
     * @param keyProvider the explicit provider to use with JwtBuilder/Parser calls or {@code null} to use the JVM default
     * provider(s).
     */
    static void testJws(Provider keyProvider) {

        def algs = [] as List<Identifiable>
        algs.addAll(Jwts.SIG.get().values().findAll({ it != Jwts.SIG.EdDSA })) // EdDSA accounted for by next two:
        algs.add(Jwks.CRV.Ed25519)
        algs.add(Jwks.CRV.Ed448)

        for (Identifiable alg : algs) {
            def signKey, verifyKey // same for Mac algorithms, priv/pub for sig algorithms
            if (alg instanceof MacAlgorithm) {
                signKey = verifyKey = findPkcs11SecretKey(alg)
            } else { // SignatureAlgorithm
                java.security.KeyPair pair = findPkcs11Pair(alg)
                signKey = pair?.private
                verifyKey = pair?.public
            }
            if (!signKey) continue // not supported by Either the SunPKCS11 provider or SoftHSM2, so we have to try next

            alg = alg instanceof Curve ? Jwts.SIG.EdDSA : alg as SecureDigestAlgorithm

            // We might need to specify the PKCS11 provider since we can't access the private key material:
            def jws = Jwts.builder().provider(keyProvider).issuer('me').signWith(signKey, alg).compact()

            def builder = Jwts.parser()
            if (verifyKey instanceof SecretKey) {
                // We only need to specify a provider during parsing for MAC HSM keys: SignatureAlgorithm verification
                // only needs the PublicKey, and a recipient doesn't need/won't have an HSM for public material anyway.
                verifyKey = Keys.builder(verifyKey).provider(keyProvider).build()
                builder.verifyWith(verifyKey as SecretKey)
            } else {
                builder.verifyWith(verifyKey as PublicKey)
            }
            String iss = builder.build().parseClaimsJws(jws).getPayload().getIssuer()

            assertEquals 'me', iss
        }
    }

    @Test
    void testJws() {
        testJws(PKCS11)
    }

    // create a jwe and then decrypt it
    static void encRoundtrip(TestKeys.Bundle bundle, def keyalg, Provider provider /* may be null */) {
        def pair = bundle.pair
        def pub = pair.public
        def priv = pair.private
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
            bundle.pair = new java.security.KeyPair(cert.getPublicKey(), priv)
            pub = bundle.pair.public
        }

        // Encryption uses the public key, and that key material is available, so no need for the PKCS11 provider:
        String jwe = Jwts.builder().issuer('me').encryptWith(pub, keyalg, Jwts.ENC.A256GCM).compact()

        // The private key can be null if SunPKCS11 doesn't support the key algorithm directly.  In this case
        // encryption only worked because generic X.509 decoding (from the key certificate in the keystore) produced the
        // public key.  So we can only decrypt if SunPKCS11 supports the private key, so check for non-null:
        if (priv) {
            // Decryption may need private material inside the HSM:
            priv = Keys.builder(pair.private).publicKey(pub).provider(provider).build()

            String iss = Jwts.parser().decryptWith(priv).build().parseClaimsJwe(jwe).getPayload().getIssuer()
            assertEquals 'me', iss
        }
    }

    static void testJwe(Provider provider) {
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
                    encRoundtrip(bundle, Jwts.KEY.RSA1_5, provider)
                } else if (StandardCurves.findByKey(bundle.pair.public) != null) { // EC or Ed key
                    // try all ECDH key algorithms:
                    Jwts.KEY.get().values().findAll({ it.id.startsWith('ECDH-ES') }).each {
                        encRoundtrip(bundle, it, provider)
                    }
                } else {
                    throw new IllegalStateException("Unexpected key algorithm: $name")
                }
            }
        }
    }

    @Test
    void testJwe() {
        testJwe(PKCS11)
    }

    /**
     * Ensures that for all JWE and JWS algorithms, when the PKCS11 provider is installed as a JVM provider, 
     * no calls to JwtBuilder/Parser .provider are needed, and no ProviderKeys (Keys.builder) calls are needed
     * anywhere in application code.*/
    @Test
    void testPkcs11JvmProviderDoesNotRequireProviderKeys() {
        if (PKCS11 == null) return; // couldn't load on MacOS (arm64 libsofthsm2.so) on JDK 7 (x86_64)
        Security.addProvider(PKCS11)
        try {
            testJws(null)
            testJwe(null)
        } finally {
            Security.removeProvider(PKCS11.getName())
        }
    }
}
