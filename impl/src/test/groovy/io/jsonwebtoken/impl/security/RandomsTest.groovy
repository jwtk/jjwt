package io.jsonwebtoken.impl.security

import org.junit.Test

import java.security.SecureRandom

import static org.junit.Assert.assertTrue

/**
 * @since JJWT_RELEASE_VERSION
 */
class RandomsTest {

    @Test
    void testPrivateCtor() { //for code coverage only
        new Randoms()
    }

    @Test
    void testSecureRandom() {
        def random = Randoms.secureRandom()
        assertTrue random instanceof SecureRandom
    }
}
