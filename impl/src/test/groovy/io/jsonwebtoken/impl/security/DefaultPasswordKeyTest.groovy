package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.Keys
import io.jsonwebtoken.security.PasswordKey
import org.junit.Before
import org.junit.Test

import static org.junit.Assert.*

@SuppressWarnings('GroovyAccessibility')
class DefaultPasswordKeyTest {

    private char[] PASSWORD
    private DefaultPasswordKey KEY

    @Before
    void setup() {
        PASSWORD = "whatever".toCharArray()
        KEY = new DefaultPasswordKey(PASSWORD)
    }

    @Test
    void testNewInstance() {
        assertArrayEquals PASSWORD, KEY.getPassword()
        assertEquals DefaultPasswordKey.NONE_ALGORITHM, KEY.getAlgorithm()
        assertEquals DefaultPasswordKey.RAW_FORMAT, KEY.getFormat()
    }

    @Test
    void testGetEncodedUnsupported() {
        try {
            KEY.getEncoded()
            fail()
        } catch (UnsupportedOperationException expected) {
            assertEquals DefaultPasswordKey.ENCODED_DISABLED_MSG, expected.getMessage()
        }
    }

    @Test
    void testSymmetricChange() {
        //assert change in backing array changes key as well:
        PASSWORD[0] = 'b'
        assertArrayEquals PASSWORD, KEY.getPassword()
    }

    @Test
    void testSymmetricDestroy() {
        KEY.destroy()
        assertTrue KEY.isDestroyed()
        for(char c : PASSWORD) { //assert clearing key clears backing array:
            assertTrue c == (char)'\u0000'
        }
    }

    @Test
    void testDestroyIdempotent() {
        testSymmetricDestroy()
        //now do it again to assert idempotent result:
        KEY.destroy()
        assertTrue KEY.isDestroyed()
        for(char c : PASSWORD) {
            assertTrue c == (char)'\u0000'
        }
    }

    @Test
    void testDestroyPreventsPassword() {
        KEY.destroy()
        try {
            KEY.getPassword()
            fail()
        } catch (IllegalStateException expected) {
            assertEquals DefaultPasswordKey.DESTROYED_MSG, expected.getMessage()
        }
    }

    @Test
    void testEquals() {
        PasswordKey key2 = Keys.forPassword(PASSWORD)
        assertArrayEquals KEY.getPassword(), key2.getPassword()
        assertEquals KEY, key2
        assertNotEquals KEY, new Object()
    }

    @Test
    void testHashCode() {
        PasswordKey key2 = Keys.forPassword(PASSWORD)
        assertArrayEquals KEY.getPassword(), key2.getPassword()
        assertEquals KEY.hashCode(), key2.hashCode()
    }

    @Test
    void testToString() {
        assertEquals 'password=<redacted>', KEY.toString()
        PasswordKey key2 = Keys.forPassword(PASSWORD)
        assertArrayEquals KEY.getPassword(), key2.getPassword()
        assertEquals KEY.toString(), key2.toString()
    }

}
