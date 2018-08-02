package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.CurveIds
import io.jsonwebtoken.security.Jwks
import org.junit.Test

import static org.junit.Assert.*

class JwksTest {

    @Test
    void testBuilder() {
        assertTrue Jwks.builder() instanceof DefaultJwkBuilderFactory
    }

    @Test
    void testBuilderSymmetric() {
        assertTrue Jwks.builder().symmetric() instanceof DefaultSymmetricJwkBuilder
    }

    @Test
    void testBuilderEc() {
        assertTrue Jwks.builder().ellipticCurve() instanceof DefaultEcJwkBuilderFactory
    }

    @Test
    void testBuilderEcPublicKey() {
        assertTrue Jwks.builder().ellipticCurve().publicKey() instanceof DefaultPublicEcJwkBuilder
    }

    @Test
    void testBuilderEcPrivateKey() {
        assertTrue Jwks.builder().ellipticCurve().privateKey() instanceof DefaultPrivateEcJwkBuilder
    }

    @Test
    void testSymmetric() {
        println Jwks.builder().symmetric().setUse("signature").setId(UUID.randomUUID().toString()).setK("foo").build()
    }

    @Test
    void testFoo() {
        println Jwks.builder().ellipticCurve().publicKey().setCurveId(CurveIds.P256).setX("xval").setY("yval").build()
        println Jwks.builder().ellipticCurve().publicKey().setCurveId(CurveIds.P384).setX("x").setY("y").build()
        println Jwks.builder().ellipticCurve().privateKey().setCurveId(CurveIds.P521).setX("x").setY("y").setD("d").build()
    }
}
