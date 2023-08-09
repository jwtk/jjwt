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

import static org.junit.Assert.assertEquals

class CompactMediaTypeIdConverterTest {

    private static final Converter<String, Object> converter = CompactMediaTypeIdConverter.INSTANCE

    @Test(expected = IllegalArgumentException)
    void testApplyToNull() {
        converter.applyTo(null)
    }

    @Test(expected = IllegalArgumentException)
    void testApplyToEmpty() {
        converter.applyTo('')
    }

    @Test(expected = IllegalArgumentException)
    void testApplyToBlank() {
        converter.applyTo('    ')
    }

    @Test(expected = IllegalArgumentException)
    void testApplyFromNull() {
        converter.applyFrom(null)
    }

    @Test(expected = IllegalArgumentException)
    void testApplyFromNonString() {
        converter.applyFrom(42)
    }

    @Test
    void testNonApplicationMediaType() {
        String cty = 'foo'
        assertEquals cty, converter.applyTo(cty)
        // must auto-prepend 'application/' if no slash in cty value
        // per https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.10:
        assertEquals "application/$cty" as String, converter.applyFrom(cty)
    }

    @Test
    void testApplicationMediaType() {
        String cty = 'foo'
        String mediaType = "application/$cty"
        // assert it has been automatically compacted per https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.10 :
        assertEquals cty, converter.applyTo(mediaType)
    }

    @Test
    void testCaseInsensitiveApplicationMediaType() { // media type values are case insensitive
        String cty = 'FoO'
        String mediaType = "aPpLiCaTiOn/$cty"
        // assert it has been automatically compacted per https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.10 :
        assertEquals cty, converter.applyTo(mediaType)
    }

    @Test
    void testApplicationMediaTypeWithMoreThanOneForwardSlash() {
        String mediaType = "application/foo;part=1/2"
        // cannot be compacted per https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.10 :
        assertEquals mediaType, converter.applyTo(mediaType)
    }

    @Test
    void testCaseInsensitiveApplicationMediaTypeWithMoreThanOneForwardSlash() {
        String mediaType = "aPpLiCaTiOn/foo;part=1/2"
        // cannot be compacted per https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.10 :
        assertEquals mediaType, converter.applyTo(mediaType)
    }

    @Test
    void testApplicationMediaTypeWithMoreThanOneForwardSlash2() {
        String mediaType = "application//test"
        // cannot be compacted per https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.10 :
        assertEquals mediaType, converter.applyTo(mediaType)
    }
}
