/*
 * Copyright (C) 2014 jsonwebtoken.io
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
package io.jsonwebtoken.impl

import org.junit.Test

import java.time.Instant

import static org.junit.Assert.*

class FixedClockTest {

    @Test
    void testFixedClockDefaultConstructor() {

        def clock = new FixedClock()

        def date1 = clock.now()
        Thread.sleep(100)
        def date2 = clock.now()

        assertEquals date1, date2
        assertNotSame date1, date2 // a new copy is returned on each call; the seed is not mutable externally
    }

    @Test
    void testFixedClockDefaultConstructorInstant() {
        def clock = new FixedClock()

        def instant1 = clock.instant()
        Thread.sleep(100)
        def instant2 = clock.instant()

        assertSame instant1, instant2
    }

    @Test
    void testInstantConstructor() {
        def instant = Instant.parse('2026-10-03T10:15:30.123Z')
        def clock = new FixedClock(instant)
        assertSame instant, clock.instant()
        assertEquals Date.from(instant), clock.now()
    }

    @Test
    void testDateConstructor() {
        def date = new Date(1700000000123L)
        def clock = new FixedClock(date)
        assertEquals date.toInstant(), clock.instant()
        assertEquals date, clock.now()
    }

    @Test
    void testNullDateConstructor() {
        def clock = new FixedClock((Date) null)
        assertNull clock.instant()
        assertNull clock.now()
    }

    @Test
    void testMillisConstructor() {
        def clock = new FixedClock(1700000000123L)
        assertEquals Instant.ofEpochMilli(1700000000123L), clock.instant()
        assertEquals new Date(1700000000123L), clock.now()
    }
}
