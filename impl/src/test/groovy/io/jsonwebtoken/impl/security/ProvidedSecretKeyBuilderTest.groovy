package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.Keys
import org.junit.Test

import static org.junit.Assert.assertSame

class ProvidedSecretKeyBuilderTest {

    @Test
    void testBuildPasswordWithoutProvider() {
        def password = Keys.password('foo'.toCharArray())
        assertSame password, Keys.builder(password).build() // does not wrap in ProviderKey
    }

    @Test
    void testBuildPasswordWithProvider() {
        def password = Keys.password('foo'.toCharArray())
        assertSame password, Keys.builder(password).provider(new TestProvider()).build() // does not wrap in ProviderKey
    }
}
