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
package io.jsonwebtoken.impl.io

import org.junit.Test

import static org.junit.Assert.assertArrayEquals
import static org.junit.Assert.assertTrue

/**
 * @since 0.12.0
 */
class TeeOutputStreamTest {

    @Test
    void flush() {
        boolean aFlushed = false
        boolean bFlushed = false
        def a = new ByteArrayOutputStream() {
            @Override
            void flush() throws IOException {
                aFlushed = true
            }
        }
        def b = new ByteArrayOutputStream() {
            @Override
            void flush() throws IOException {
                bFlushed = true
            }
        }
        def tee = new TeeOutputStream(a, b)
        tee.flush()
        assertTrue aFlushed
        assertTrue bFlushed
    }

    @Test
    void close() {
        boolean aClosed = false
        boolean bClosed = false
        def a = new ByteArrayOutputStream() {
            @Override
            void close() throws IOException {
                aClosed = true
            }
        }
        def b = new ByteArrayOutputStream() {
            @Override
            void close() throws IOException {
                bClosed = true
            }
        }
        def tee = new TeeOutputStream(a, b)
        tee.close()
        assertTrue aClosed
        assertTrue bClosed
    }

    @Test
    void writeByte() {
        def a = new ByteArrayOutputStream()
        def b = new ByteArrayOutputStream()
        def tee = new TeeOutputStream(a, b)
        byte aByte = 0x15 as byte // any random value is fine
        byte[] expected = new byte[1]; expected[0] = aByte

        tee.write(aByte)

        assertArrayEquals expected, a.toByteArray()
        assertArrayEquals expected, b.toByteArray()
    }
}
