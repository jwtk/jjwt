/*
 * Copyright © 2023 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.jsonwebtoken.impl.lang

import io.jsonwebtoken.impl.security.KeysBridge
import io.jsonwebtoken.impl.security.TestKeys
import org.junit.Test

import javax.crypto.spec.SecretKeySpec
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
        String msg = 'bar'
        def ex = new InvocationTargetException(new IllegalStateException('foo'), msg)
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
            assertEquals ReflectionFunction.ERR_MSG + msg, ise.getMessage()
            assertSame ex, ise.getCause()
        }
    }

    @Test
    void testStatic() {
        def i = new OptionalMethodInvoker(KeysBridge.class.getName(), "findBitLength", Key.class, true)
        int bits = 256
        def key = new SecretKeySpec(Bytes.random((int)(bits / 8)), "AES")
        assertEquals bits, i.apply(key)
    }
}
