package io.jsonwebtoken.impl.lang

import io.jsonwebtoken.impl.security.TestKeys
import org.junit.Test

import java.lang.reflect.InvocationTargetException
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
    void testClassAndMethodExistWithValidArgument() {
        def key = TestKeys.HS256
        def i = new OptionalMethodInvoker(Key.class.getName(), 'getAlgorithm')
        assertEquals key.getAlgorithm(), i.apply(key)
    }

    @Test
    void testClassAndMethodExistWithInvalidTypeArgument() {
        def i = new OptionalMethodInvoker(Key.class.getName(), 'getAlgorithm')
        assertNull i.apply('Hello') // not a Key instance, should return null
    }

    @Test
    void testClassAndMethodExistWithInvocationError() {
        def key = TestKeys.HS256
        def ex = new InvocationTargetException()
        def i = new OptionalMethodInvoker<Key, String>(Key.class.getName(), 'getEncoded') {
            @Override
            protected String invoke(Key aKey) throws InvocationTargetException, IllegalAccessException {
                throw ex
            }
        }
        try {
            i.apply(key) // getEncoded returns a byte array, not a String, should throw cast error
            fail()
        } catch (IllegalStateException ise) {
            assertEquals ReflectionFunction.ERR_MSG + "null", ise.getMessage()
            assertSame ex, ise.getCause()
        }
    }
}
