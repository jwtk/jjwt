package io.jsonwebtoken.security

import org.junit.Test
import static org.junit.Assert.*

/**
 * @since JJWT_RELEASE_VERSION
 */
class KeyManagementModeNameTest {

    @Test
    void test() {
        //todo, write a real test:
        for(KeyManagementModeName modeName : KeyManagementModeName.values()) {
            assertNotNull modeName.getName()
            assertNotNull modeName.getDescription()
        }
    }
}
