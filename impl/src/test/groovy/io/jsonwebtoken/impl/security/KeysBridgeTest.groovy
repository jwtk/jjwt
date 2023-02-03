package io.jsonwebtoken.impl.security


import org.junit.Test

import java.security.Key

import static org.junit.Assert.assertEquals

class KeysBridgeTest {

    @Test
    void testToStringKeyNull() {
        assertEquals 'null', KeysBridge.toString(null)
    }

    @Test
    void testToStringPublicKey() {
        // should just be key.toString(). Because it's a PublicKey, no danger of reporting key data
        def key = TestKeys.ES256.pair.public
        String s = KeysBridge.toString(key)
        assertEquals key.toString(), s
    }

    static void testFormattedOutput(Key key) {
        String s = KeysBridge.toString(key)
        String expected = "class: ${key.getClass().getName()}, algorithm: ${key.getAlgorithm()}, format: ${key.getFormat()}" as String
        assertEquals expected, s
    }

    @Test
    void testToStringPrivateKey() {
        testFormattedOutput(TestKeys.ES256.pair.private)
    }

    @Test
    void testToStringSecretKey() {
        testFormattedOutput(TestKeys.HS256)
    }

    @Test
    void testToStringPassword() {
        testFormattedOutput(new PasswordSpec("foo".toCharArray()))
    }
}
