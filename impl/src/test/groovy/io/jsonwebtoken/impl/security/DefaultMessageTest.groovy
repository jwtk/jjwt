package io.jsonwebtoken.impl.security

import org.junit.Test

class DefaultMessageTest {

    @Test(expected = IllegalArgumentException)
    void testNullData() {
        new DefaultMessage(null)
    }

    @Test(expected = IllegalArgumentException)
    void testEmptyByteArrayData() {
        new DefaultMessage(new byte[0])
    }
}
