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

import org.junit.Test

import javax.crypto.spec.PBEKeySpec

import static org.junit.Assert.*

class OptionalCtorInvokerTest {

    @Test
    void testCtorWithClassArg() {
        String foo = 'test'
        def fn = new OptionalCtorInvoker<>("java.lang.String", String.class) // copy constructor
        def result = fn.apply(foo)
        assertEquals foo, result
    }

    @Test
    void testCtorWithFqcnArg() {
        String foo = 'test'
        def fn = new OptionalCtorInvoker<>("java.lang.String", "java.lang.String") // copy constructor
        def result = fn.apply(foo)
        assertEquals foo, result
    }

    @Test
    void testCtorWithMultipleMixedArgTypes() {
        char[] chars = "foo".toCharArray()
        byte[] salt = [0x00, 0x01, 0x02, 0x03] as byte[]
        int iterations = 256
        def fn = new OptionalCtorInvoker<>("javax.crypto.spec.PBEKeySpec", char[].class, byte[].class, int.class) //password, salt, iteration count
        def args = [chars, salt, iterations] as Object[]
        def result = fn.apply(args) as PBEKeySpec
        assertArrayEquals chars, result.getPassword()
        assertArrayEquals salt, result.getSalt()
        assertEquals iterations, result.getIterationCount()
    }

    @Test
    void testZeroArgConstructor() {
        OptionalCtorInvoker fn = new OptionalCtorInvoker("java.util.LinkedHashMap")
        Object args = null
        def result = fn.apply(args)
        assertTrue result instanceof LinkedHashMap
    }

    @Test
    void testMissingConstructor() {
        def fn = new OptionalCtorInvoker('com.foo.Bar')
        assertNull fn.apply(null)
    }
}
