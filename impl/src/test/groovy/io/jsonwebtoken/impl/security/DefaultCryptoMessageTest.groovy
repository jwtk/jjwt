package io.jsonwebtoken.impl.security

import org.junit.Test

class DefaultCryptoMessageTest {

    @Test(expected = IllegalArgumentException)
    void testNullData() {
        new DefaultCryptoMessage<>(null)
    }

    @Test(expected = IllegalArgumentException)
    void testEmptyByteArrayData() {
        new DefaultCryptoMessage<>(new byte[0])
    }
}
