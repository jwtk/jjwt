/*
 * Copyright (C) 2022 jsonwebtoken.io
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
package io.jsonwebtoken.jackson.io


import io.jsonwebtoken.lang.Supplier
import org.junit.Test

import static org.junit.Assert.assertEquals

class JacksonSupplierSerializerTest {

    @Test
    void testSupplierNullValue() {
        def serializer = new JacksonWriter()
        def supplier = new Supplier() {
            @Override
            Object get() {
                return null
            }
        }
        StringWriter w = new StringWriter(4)
        serializer.write(w, supplier)
        assertEquals 'null', w.toString()
    }

    @Test
    void testSupplierStringValue() {
        def serializer = new JacksonWriter()
        def supplier = new Supplier() {
            @Override
            Object get() {
                return 'hello'
            }
        }
        StringWriter w = new StringWriter(7)
        serializer.write(w, supplier)
        assertEquals '"hello"', w.toString()
    }
}
