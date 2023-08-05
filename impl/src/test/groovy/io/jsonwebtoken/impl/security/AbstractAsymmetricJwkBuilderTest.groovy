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

import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.security.*
import org.junit.Test

import java.security.cert.X509Certificate
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

import static org.junit.Assert.*

class AbstractAsymmetricJwkBuilderTest {

    private static final X509Certificate CERT = TestKeys.RS256.cert
    private static final List<X509Certificate> CHAIN = [CERT]
    private static final RSAPublicKey PUB_KEY = CERT.getPublicKey() as RSAPublicKey

    private static RsaPublicJwkBuilder builder() {
        return Jwks.builder().key(PUB_KEY)
    }

    @Test
    void testUse() {
        def val = UUID.randomUUID().toString()
        def jwk = builder().publicKeyUse(val).build()
        assertEquals val, jwk.getPublicKeyUse()
        assertEquals val, jwk.use

        RSAPrivateKey privateKey = TestKeys.RS256.pair.private as RSAPrivateKey

        jwk = builder().publicKeyUse(val).privateKey(privateKey).build()
        assertEquals val, jwk.getPublicKeyUse()
        assertEquals val, jwk.use
    }

    @Test
    void testX509Url() {
        def val = new URI(UUID.randomUUID().toString())
        assertSame val, builder().x509Url(val).build().getX509Url()
    }

    @Test
    void testX509CertificateChain() {
        assertEquals CHAIN, builder().x509CertificateChain(CHAIN).build().getX509CertificateChain()
    }

    @Test
    void testX509CertificateSha1Thumbprint() {
        Request<byte[]> request = new DefaultRequest(TestKeys.RS256.cert.getEncoded(), null, null)
        def x5t = DefaultHashAlgorithm.SHA1.digest(request)
        def encoded = Encoders.BASE64URL.encode(x5t)
        def jwk = builder().x509CertificateSha1Thumbprint(x5t).build()
        assertArrayEquals x5t, jwk.getX509CertificateSha1Thumbprint()
        assertEquals encoded, jwk.get(AbstractAsymmetricJwk.X5T.getId())
    }

    @Test
    void testX509CertificateSha1ThumbprintEnabled() {
        Request<byte[]> request = new DefaultRequest(TestKeys.RS256.cert.getEncoded(), null, null)
        def x5t = DefaultHashAlgorithm.SHA1.digest(request)
        def encoded = Encoders.BASE64URL.encode(x5t)
        def jwk = builder().x509CertificateChain(CHAIN).withX509Sha1Thumbprint(true).build()
        assertArrayEquals x5t, jwk.getX509CertificateSha1Thumbprint()
        assertEquals encoded, jwk.get(AbstractAsymmetricJwk.X5T.getId())
    }

    @Test
    void testX509CertificateSha256Thumbprint() {
        Request<byte[]> request = new DefaultRequest(TestKeys.RS256.cert.getEncoded(), null, null)
        def x5tS256 = Jwks.HASH.SHA256.digest(request)
        def encoded = Encoders.BASE64URL.encode(x5tS256)
        def jwk = builder().x509CertificateSha256Thumbprint(x5tS256).build()
        assertArrayEquals x5tS256, jwk.getX509CertificateSha256Thumbprint()
        assertEquals encoded, jwk.get(AbstractAsymmetricJwk.X5T_S256.getId())
    }

    @Test
    void testX509CertificateSha256ThumbprintEnabled() {
        Request<byte[]> request = new DefaultRequest(TestKeys.RS256.cert.getEncoded(), null, null)
        def x5tS256 = Jwks.HASH.SHA256.digest(request)
        def encoded = Encoders.BASE64URL.encode(x5tS256)
        def jwk = builder().x509CertificateChain(CHAIN).withX509Sha256Thumbprint(true).build()
        assertArrayEquals x5tS256, jwk.getX509CertificateSha256Thumbprint()
        assertEquals encoded, jwk.get(AbstractAsymmetricJwk.X5T_S256.getId())
    }

    @Test
    void testEcPrivateJwkFromPublicBuilder() {
        def pair = TestKeys.ES256.pair

        //start with a public key builder
        def builder = Jwks.builder().key(pair.public as ECPublicKey)
        assertTrue builder instanceof AbstractAsymmetricJwkBuilder.DefaultEcPublicJwkBuilder

        //applying the private key turns it into a private key builder
        builder = builder.privateKey(pair.private as ECPrivateKey)
        assertTrue builder instanceof AbstractAsymmetricJwkBuilder.DefaultEcPrivateJwkBuilder

        //building creates a private jwk:
        def jwk = builder.build()
        assertTrue jwk instanceof EcPrivateJwk

        //which also has information for the public key:
        jwk = jwk.toPublicJwk()
        assertTrue jwk instanceof EcPublicJwk
    }
}
