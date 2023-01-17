package io.jsonwebtoken.impl.lang


import io.jsonwebtoken.impl.security.TestKeys
import org.junit.Test

import java.security.Key

import static org.junit.Assert.*

class OptionalMethodInvokerTest {

    @Test
    void testClassDoesNotExist() {
        def i = new OptionalMethodInvoker('com.foo.Bar', 'foo')
        assertNull i.apply(null)
    }

    @Test
    void testClassExistsButMethodDoesNotExist() {
        def i = new OptionalMethodInvoker(Key.class.getName(), 'foo')
        assertNull i.apply(null)
    }

    @Test
    void testClassAndMethodExist() {
        def key = TestKeys.HS256
        def i = new OptionalMethodInvoker(Key.class.getName(), 'getAlgorithm')
        assertEquals key.getAlgorithm(), i.apply(key)
    }

    @Test
    void testClassAndMethodExistWithInvocationError() {
        def i = new OptionalMethodInvoker(Key.class.getName(), 'getAlgorithm')
        //invoke with a non-key instance:
        try {
            i.apply("Hello")
            fail()
        } catch (IllegalStateException ex) {
            assertNotNull(ex.getCause())
            String msg = OptionalMethodInvoker.ERR_MSG + ex.getCause().getMessage()
            assertEquals(msg, ex.getMessage())
        }
    }
}
