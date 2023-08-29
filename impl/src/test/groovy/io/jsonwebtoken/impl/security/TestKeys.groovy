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
import io.jsonwebtoken.security.Jwks

import javax.crypto.SecretKey
import java.security.KeyPair
import java.security.PrivateKey
import java.security.Provider
import java.security.PublicKey
import java.security.cert.X509Certificate

/**
 * Test helper with cached keys to save time across tests (so we don't have to constantly dynamically generate keys)
 */
class TestKeys {

    static Provider BC = TestCertificates.BC

    // =======================================================
    // Secret Keys
    // =======================================================
    static SecretKey HS256 = Jwts.SIG.HS256.key().build()
    static SecretKey HS384 = Jwts.SIG.HS384.key().build()
    static SecretKey HS512 = Jwts.SIG.HS512.key().build()
    static Collection<SecretKey> HS = Collections.setOf(HS256, HS384, HS512)

    static SecretKey A128GCM, A192GCM, A256GCM, A128KW, A192KW, A256KW, A128GCMKW, A192GCMKW, A256GCMKW
    static Collection<SecretKey> AGCM
    static {
        A128GCM = A128KW = A128GCMKW = Jwts.ENC.A128GCM.key().build()
        A192GCM = A192KW = A192GCMKW = Jwts.ENC.A192GCM.key().build()
        A256GCM = A256KW = A256GCMKW = Jwts.ENC.A256GCM.key().build()
        AGCM = Collections.setOf(A128GCM, A192GCM, A256GCM)
    }

    static SecretKey A128CBC_HS256 = Jwts.ENC.A128CBC_HS256.key().build()
    static SecretKey A192CBC_HS384 = Jwts.ENC.A192CBC_HS384.key().build()
    static SecretKey A256CBC_HS512 = Jwts.ENC.A256CBC_HS512.key().build()
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
    static Bundle ES256 = TestCertificates.readBundle(Jwts.SIG.ES256)
    static Bundle ES384 = TestCertificates.readBundle(Jwts.SIG.ES384)
    static Bundle ES512 = TestCertificates.readBundle(Jwts.SIG.ES512)
    static Set<Bundle> EC = Collections.setOf(ES256, ES384, ES512)

    static Bundle Ed25519 = TestCertificates.readBundle(Jwks.CRV.Ed25519)
    static Bundle Ed448 = TestCertificates.readBundle(Jwks.CRV.Ed448)
    // just an alias for Ed448 for now:
    static Bundle EdDSA = Ed448
    static Bundle X25519 = TestCertificates.readBundle(EdwardsCurve.X25519)
    static Bundle X448 = TestCertificates.readBundle(EdwardsCurve.X448)
    static Set<Bundle> EdEC = Collections.setOf(EdDSA, Ed25519, Ed448, X25519, X448)

    // =======================================================
    // RSA Keys & Certificates
    // =======================================================
    static Bundle RS256 = TestCertificates.readBundle(Jwts.SIG.RS256)
    static Bundle RS384 = TestCertificates.readBundle(Jwts.SIG.RS384)
    static Bundle RS512 = TestCertificates.readBundle(Jwts.SIG.RS512)
    static Bundle PS256 = TestCertificates.readBundle(Jwts.SIG.PS256)
    static Bundle PS384 = TestCertificates.readBundle(Jwts.SIG.PS384)
    static Bundle PS512 = TestCertificates.readBundle(Jwts.SIG.PS512)
//    static Set<Bundle> PKCSv15 = Collections.setOf(RS256, RS384, RS512)
//    static Set<Bundle> RSASSA_PSS = Collections.setOf(PS256, PS384, PS512)
    static Set<Bundle> RSA = Collections.setOf(RS256, RS384, RS512, PS256, PS384, PS512)

    static Set<Bundle> ASYM = new LinkedHashSet<>()
    static {
        ASYM.addAll(EC)
        ASYM.addAll(EdEC)
        ASYM.addAll(RSA)
    }

    static Bundle forAlgorithm(Identifiable alg) {
        String id = alg.getId()
        return TestKeys.metaClass.getAttribute(TestKeys, id) as Bundle
    }

    static class Bundle {

        Identifiable alg
        X509Certificate cert
        List<X509Certificate> chain
        KeyPair pair

        Bundle(Identifiable alg, PublicKey publicKey, PrivateKey privateKey, X509Certificate cert = null) {
            this.alg = alg
            this.cert = cert
            this.chain = cert != null ? Collections.of(cert) : Collections.<X509Certificate> emptyList()
            this.pair = new KeyPair(publicKey, privateKey);
        }
    }
}
