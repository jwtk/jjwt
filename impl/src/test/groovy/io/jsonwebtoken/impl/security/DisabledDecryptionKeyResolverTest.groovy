package io.jsonwebtoken.impl.security

import org.junit.Test

import static org.junit.Assert.assertNull

/**
 * @since JJWT_RELEASE_VERSION
 */
class DisabledDecryptionKeyResolverTest {

    @Test
    void test() {
        assertNull DisabledDecryptionKeyResolver.INSTANCE.resolveDecryptionKey(null)
    }
}
