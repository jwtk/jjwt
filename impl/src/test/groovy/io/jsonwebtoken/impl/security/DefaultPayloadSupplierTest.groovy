package io.jsonwebtoken.impl.security

import org.junit.Test

class DefaultPayloadSupplierTest {

    @Test(expected = IllegalArgumentException)
    void testNullData() {
        new DefaultPayloadSupplier<>(null)
    }

    @Test(expected = IllegalArgumentException)
    void testEmptyByteArrayData() {
        new DefaultPayloadSupplier<>(new byte[0])
    }
}
