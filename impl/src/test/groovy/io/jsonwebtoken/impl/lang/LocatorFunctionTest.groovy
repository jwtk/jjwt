/*
 * Copyright (C) 2021 jsonwebtoken.io
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

import io.jsonwebtoken.Header
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.Locator
import org.junit.Test

import static org.junit.Assert.assertEquals

class LocatorFunctionTest {

    @Test
    void testApply() {
        final int value = 42
        def locator = new StaticLocator(value)
        def fn = new LocatorFunction(locator)
        assertEquals value, fn.apply(Jwts.header().build())
    }

    static class StaticLocator<T> implements Locator<T> {
        private final T o;

        StaticLocator(T o) {
            this.o = o;
        }

        @Override
        T locate(Header header) {
            return o;
        }
    }
}
