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
package io.jsonwebtoken.lang

import org.junit.Test

import java.text.SimpleDateFormat

import static org.junit.Assert.*

class DateFormatsTest {

    @Test //https://github.com/jwtk/jjwt/issues/291
    void testUtcTimezone() {

        def iso8601 = DateFormats.ISO_8601.get()
        def iso8601Millis = DateFormats.ISO_8601_MILLIS.get()

        assertTrue iso8601 instanceof SimpleDateFormat
        assertTrue iso8601Millis instanceof SimpleDateFormat

        def utc = TimeZone.getTimeZone("UTC")

        assertEquals utc, iso8601.getTimeZone()
        assertEquals utc, iso8601Millis.getTimeZone()
    }
}
