/*
 * Copyright (C) 2026 jsonwebtoken.io
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
package io.jsonwebtoken

import org.junit.Test

import java.time.Instant

import static org.junit.Assert.assertEquals

class ClockTest {

    @Test
    void testDefaultInstantDelegatesToNow() {
        def date = new Date(1700000000123L)
        Clock clock = new Clock() {
            @Override
            Date now() {
                return date
            }
        }
        assertEquals date.toInstant(), clock.instant()
    }

    @Test
    void testDefaultInstantWithLambdaClock() {
        def date = new Date(1700000000123L)
        Clock clock = { -> date } as Clock
        assertEquals Instant.ofEpochMilli(1700000000123L), clock.instant()
    }

    @Test
    void testDefaultInstantReflectsEachNowInvocation() {
        def millis = 1000L
        Clock clock = { -> new Date(millis++) } as Clock
        assertEquals Instant.ofEpochMilli(1000L), clock.instant()
        assertEquals Instant.ofEpochMilli(1001L), clock.instant()
    }

    @Test
    void testOverriddenInstant() {
        def fixed = Instant.ofEpochSecond(1700000000L, 123456789L)
        Clock clock = new Clock() {
            @Override
            Date now() {
                return Date.from(instant())
            }

            @Override
            Instant instant() {
                return fixed
            }
        }
        assertEquals fixed, clock.instant()
        assertEquals Date.from(fixed), clock.now()
    }
}
