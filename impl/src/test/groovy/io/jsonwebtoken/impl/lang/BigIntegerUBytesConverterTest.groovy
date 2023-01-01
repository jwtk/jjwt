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

import io.jsonwebtoken.io.Decoders
import org.junit.Test

import static org.junit.Assert.*

class BigIntegerUBytesConverterTest {

    private BigIntegerUBytesConverter CONVERTER = Converters.BIGINT_UBYTES as BigIntegerUBytesConverter

    @Test
    void testNegative() {
        try {
            CONVERTER.applyTo(BigInteger.valueOf(-1))
            fail()
        } catch (IllegalArgumentException expected) {
            assertEquals BigIntegerUBytesConverter.NEGATIVE_MSG, expected.getMessage()
        }
    }

    @Test
    void testZero() {
        byte[] result = CONVERTER.applyTo(BigInteger.ZERO)
        assertEquals 1, result.length
        assertTrue result[0] == 0x00 as byte
    }

    @Test
    void testStripSignByte() {
        BigInteger val = BigInteger.valueOf(128)
        byte[] bytes = val.toByteArray()
        byte[] result = CONVERTER.applyTo(val)
        assertEquals bytes.length - 1, result.length
    }

    /**
     * Asserts security considerations in https://www.rfc-editor.org/rfc/rfc7638#section-7, 4th paragraph.
     */
    @Test
    void testStripLeadingZeroBytes() {

        byte[] bytes1 = Decoders.BASE64URL.decode("AAEAAQ")
        byte[] bytes2 = Decoders.BASE64URL.decode("AQAB")

        BigInteger bi1 = CONVERTER.applyFrom(bytes1)
        BigInteger bi2 = CONVERTER.applyFrom(bytes2)

        assertEquals bi1, bi2
    }

    /**
     * Asserts https://www.rfc-editor.org/rfc/rfc7518.html#section-2, 'Base64urlUInt' definition, last sentence:
     * <pre>Zero is represented as BASE64URL(single zero-valued octet), which is "AA".</pre>
     */
    @Test
    void testZeroProducesAABase64Url() {
        assertEquals 'AA', Converters.BIGINT.applyTo(BigInteger.ZERO)
    }
}
