package io.jsonwebtoken.impl.security

import io.jsonwebtoken.impl.lang.Bytes
import io.jsonwebtoken.security.Keys
import org.junit.Test

import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import java.security.Provider

import static org.junit.Assert.assertSame

class ProvidedKeyBuilderTest {

    @Test
    void testBuildWithSpecifiedProviderKey() {
        Provider provider = new TestProvider()
        SecretKey key = new SecretKeySpec(Bytes.random(256), 'AES')
        def providerKey = Keys.builder(key).provider(provider).build() as ProviderSecretKey

        assertSame provider, providerKey.getProvider()
        assertSame key, providerKey.getKey()

        // now for the test: ensure that our provider key isn't wrapped again
        SecretKey returned = Keys.builder(providerKey).provider(new TestProvider('different')).build()

        assertSame providerKey, returned // not wrapped again
    }
}
