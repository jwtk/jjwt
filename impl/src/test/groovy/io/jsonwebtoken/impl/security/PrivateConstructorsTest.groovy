package io.jsonwebtoken.impl.security

import io.jsonwebtoken.impl.lang.Conditions
import io.jsonwebtoken.lang.Classes
import org.junit.Test

class PrivateConstructorsTest {

    @Test
    void testPrivateCtors() { // for code coverage only
        new Classes()
        new SignatureAlgorithmsBridge()
        new EncryptionAlgorithmsBridge()
        new KeyAlgorithmsBridge()
        new KeysBridge()
        new Conditions()
    }
}
