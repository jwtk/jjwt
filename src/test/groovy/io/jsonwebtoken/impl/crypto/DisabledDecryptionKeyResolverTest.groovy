package io.jsonwebtoken.impl.crypto

import org.junit.Test
import static org.junit.Assert.*

class DisabledDecryptionKeyResolverTest {

    @Test
    void test() {
        assertNull DisabledDecryptionKeyResolver.INSTANCE.resolveDecryptionKey(null)
    }
}
