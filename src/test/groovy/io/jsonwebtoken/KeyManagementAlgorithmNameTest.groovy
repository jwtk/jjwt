package io.jsonwebtoken

import org.junit.Test
import static org.junit.Assert.*

class KeyManagementAlgorithmNameTest {

    @Test
    void testToString() {
        for( def name : KeyManagementAlgorithmName.values()) {
            assertEquals name.value, name.toString()
        }
    }

    @Test
    void testGetDescription() {
        for( def name : KeyManagementAlgorithmName.values()) {
            assertNotNull name.getDescription() //TODO improve this for actual value testing
        }
    }

    @Test
    void testGetMoreHeaderParams() {
        for( def name : KeyManagementAlgorithmName.values()) {
            assertNotNull name.getMoreHeaderParams() //TODO improve this for actual value testing
        }
    }

    @Test
    void testGetJcaName() {
        for( def name : KeyManagementAlgorithmName.values()) {
            assertNotNull name.getJcaName() //TODO improve this for actual value testing
        }
    }

    @Test
    void testForName() {
        def name = KeyManagementAlgorithmName.forName('A128KW')
        assertSame name, KeyManagementAlgorithmName.A128KW
    }

    @Test
    void testForNameFailure() {
        try {
            KeyManagementAlgorithmName.forName('foo')
            fail()
        } catch (IllegalArgumentException expected) {
        }
    }
}

