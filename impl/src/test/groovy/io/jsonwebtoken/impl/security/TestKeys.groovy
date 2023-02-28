/*
 * Copyright (C) 2021 jsonwebtoken.io
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
import io.jsonwebtoken.lang.Collections
import io.jsonwebtoken.security.KeyBuilderSupplier
import io.jsonwebtoken.security.SecretKeyBuilder
import io.jsonwebtoken.security.SignatureAlgorithm

import javax.crypto.SecretKey
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.X509Certificate

/**
 * Test helper with cached keys to save time across tests (so we don't have to constantly dynamically generate keys)
 */
class TestKeys {

    // =======================================================
    // Secret Keys
    // =======================================================
    static SecretKey HS256 = Jwts.SIG.HS256.keyBuilder().build()
    static SecretKey HS384 = Jwts.SIG.HS384.keyBuilder().build()
    static SecretKey HS512 = Jwts.SIG.HS512.keyBuilder().build()
    static Collection<SecretKey> HS = Collections.setOf(HS256, HS384, HS512)

    static SecretKey A128GCM, A192GCM, A256GCM, A128KW, A192KW, A256KW, A128GCMKW, A192GCMKW, A256GCMKW
    static Collection<SecretKey> AGCM
    static {
        A128GCM = A128KW = A128GCMKW = Jwts.ENC.A128GCM.keyBuilder().build()
        A192GCM = A192KW = A192GCMKW = Jwts.ENC.A192GCM.keyBuilder().build()
        A256GCM = A256KW = A256GCMKW = Jwts.ENC.A256GCM.keyBuilder().build()
        AGCM = Collections.setOf(A128GCM, A192GCM, A256GCM)
    }

    static SecretKey A128CBC_HS256 = Jwts.ENC.A128CBC_HS256.keyBuilder().build()
    static SecretKey A192CBC_HS384 = Jwts.ENC.A192CBC_HS384.keyBuilder().build()
    static SecretKey A256CBC_HS512 = Jwts.ENC.A256CBC_HS512.keyBuilder().build()
    static Collection<SecretKey> ACBC = Collections.setOf(A128CBC_HS256, A192CBC_HS384, A256CBC_HS512)

    static Collection<SecretKey> SECRET = new LinkedHashSet<>()
    static {
        SECRET.addAll(HS)
        SECRET.addAll(AGCM)
        SECRET.addAll(ACBC)
    }

    // =======================================================
    // Elliptic Curve Keys & Certificates
    // =======================================================
    static Bundle ES256 = TestCertificates.readAsymmetricBundle(Jwts.SIG.ES256)
    static Bundle ES384 = TestCertificates.readAsymmetricBundle(Jwts.SIG.ES384)
    static Bundle ES512 = TestCertificates.readAsymmetricBundle(Jwts.SIG.ES512)
    static Set<Bundle> EC = Collections.setOf(ES256, ES384, ES512)

    static Bundle EdDSA = TestCertificates.readAsymmetricBundle(Jwts.SIG.EdDSA)
    static Bundle Ed25519 = TestCertificates.readAsymmetricBundle(Jwts.SIG.Ed25519)
    static Bundle Ed448 = TestCertificates.readAsymmetricBundle(Jwts.SIG.Ed448)
    static Bundle X25519 = TestCertificates.readBundle(EdwardsCurve.X25519)
    static Bundle X448 = TestCertificates.readBundle(EdwardsCurve.X448)
    static Set<Bundle> EdEC = Collections.setOf(EdDSA, Ed25519, Ed448, X25519, X448)

    // =======================================================
    // RSA Keys & Certificates
    // =======================================================
    static Bundle RS256 = TestCertificates.readAsymmetricBundle(Jwts.SIG.RS256)
    static Bundle RS384 = TestCertificates.readAsymmetricBundle(Jwts.SIG.RS384)
    static Bundle RS512 = TestCertificates.readAsymmetricBundle(Jwts.SIG.RS512)
    static Set<Bundle> RSA = Collections.setOf(RS256, RS384, RS512)

    static Set<Bundle> ASYM = new LinkedHashSet<>()
    static {
        ASYM.addAll(EC)
        ASYM.addAll(EdEC)
        ASYM.addAll(RSA)
    }

    static <T extends KeyBuilderSupplier<SecretKey, SecretKeyBuilder> & Identifiable> SecretKey forAlgorithm(T alg) {
        String id = alg.getId()
        if (id.contains('-')) {
            id = id.replace('-', '_')
        }
        return TestKeys.metaClass.getAttribute(TestKeys, id) as SecretKey
    }

    static Bundle forAlgorithm(SignatureAlgorithm alg) {
        String id = alg.getId()
        if (id.startsWith('PS')) {
            id = 'R' + id.substring(1) //keys for PS* algs are the same as RS algs
        }
        if (alg instanceof EdSignatureAlgorithm) {
            id = alg.preferredCurve.getId()
        }
        return TestKeys.metaClass.getAttribute(TestKeys, id) as Bundle
    }

    static Bundle forCurve(EdwardsCurve curve) {
        return TestKeys.metaClass.getAttribute(TestKeys, curve.getId()) as Bundle
    }

    static class Bundle {
        X509Certificate cert
        List<X509Certificate> chain
        KeyPair pair

        Bundle(X509Certificate cert, PrivateKey privateKey) {
            this.cert = cert
            this.chain = Collections.of(cert)
            this.pair = new KeyPair(cert.getPublicKey(), privateKey)
        }
        Bundle(PublicKey pub, PrivateKey priv) {
            this.cert = null
            this.chain = Collections.emptyList()
            this.pair = new KeyPair(pub, priv)
        }
    }
}
