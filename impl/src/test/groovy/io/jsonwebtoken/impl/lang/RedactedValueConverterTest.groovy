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
package io.jsonwebtoken.impl.lang

import org.junit.Test

import static org.junit.Assert.assertNull
import static org.junit.Assert.assertSame

class RedactedValueConverterTest {

    @Test
    void testApplyToWithNullValue() {
        def c = new RedactedValueConverter(new NullSafeConverter<URI, Object>(Converters.URI))
        assertNull c.applyTo(null)
    }

    @Test
    void testApplyFromWithNullValue() {
        def c = new RedactedValueConverter(new NullSafeConverter<URI, Object>(Converters.URI))
        assertNull c.applyFrom(null)
    }

    @Test
    void testDelegateReturnsRedactedSupplierValue() {
        def suri = 'https://jsonwebtoken.io'
        def supplier = new RedactedSupplier(suri)
        def delegate = new Converter() {
            @Override
            Object applyTo(Object o) {
                return supplier
            }

            @Override
            Object applyFrom(Object o) {
                return null
            }
        }
        def c = new RedactedValueConverter(delegate)

        // ensure applyTo doesn't change or wrap the delegate return value that is already of type RedactedSupplier:
        assertSame supplier, c.applyTo(suri)
    }
}
