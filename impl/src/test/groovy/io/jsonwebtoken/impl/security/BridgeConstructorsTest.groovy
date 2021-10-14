package io.jsonwebtoken.impl.security

import org.junit.Test

class BridgeConstructorsTest {

    @Test
    void testPrivateCtors() { // for code coverage only
        new SignatureAlgorithmsBridge()
        new EncryptionAlgorithmsBridge()
        new KeyAlgorithmsBridge()
        new KeysBridge()
    }
}
