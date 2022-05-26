package io.jsonwebtoken.impl.security

import io.jsonwebtoken.impl.DefaultClaims
import io.jsonwebtoken.impl.DefaultJwsHeader
import org.junit.Test

import static org.junit.Assert.assertSame

class LocatingKeyResolverTest {

    @Test(expected = IllegalArgumentException)
    void testNullConstructor() {
        new LocatingKeyResolver(null)
    }

    @Test
    void testResolveSigningKeyClaims() {
        def key = TestKeys.HS256
        def locator = new ConstantKeyLocator(key, null)
        def header = new DefaultJwsHeader()
        def claims = new DefaultClaims()
        assertSame key, new LocatingKeyResolver(locator).resolveSigningKey(header, claims)
    }

    @Test
    void testResolveSigningKeyPayload() {
        def key = TestKeys.HS256
        def locator = new ConstantKeyLocator(key, null)
        def header = new DefaultJwsHeader()
        def payload = 'hello world'
        assertSame key, new LocatingKeyResolver(locator).resolveSigningKey(header, payload)
    }
}
