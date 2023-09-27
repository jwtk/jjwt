/*
 * Copyright (C) 2015 jsonwebtoken.io
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
package io.jsonwebtoken.impl.compression

import io.jsonwebtoken.CompressionException
import io.jsonwebtoken.impl.lang.Bytes
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertSame

/**
 * @since 0.6.0
 */
class AbstractCompressionAlgorithmTest {

    @Test
    void testCompressNull() {
        def alg = new ExceptionThrowingAlgorithm()
        assertSame Bytes.EMPTY, alg.compress((byte[])null)
    }

    @Test
    void testCompressEmpty() {
        def alg = new ExceptionThrowingAlgorithm()
        assertSame Bytes.EMPTY, alg.compress(new byte[0])
    }

    @Test(expected = CompressionException.class)
    void testCompressWithException() {
        def alg = new ExceptionThrowingAlgorithm()
        alg.compress(new byte[1])
    }

    @Test
    void testDecompressEmpty() {
        def alg = new ExceptionThrowingAlgorithm()
        assertSame Bytes.EMPTY, alg.decompress(new byte[0])
    }

    @Test(expected = CompressionException.class)
    void testDecompressWithException() {
        def alg = new ExceptionThrowingAlgorithm()
        alg.decompress(new byte[1])
    }

    @Test
    void testGetId() {
        assertEquals "Test", new ExceptionThrowingAlgorithm().getId()
    }

    @Test
    void testAlgorithmName() {
        assertEquals "Test", new ExceptionThrowingAlgorithm().getAlgorithmName()
    }

    static class ExceptionThrowingAlgorithm extends AbstractCompressionAlgorithm {

        ExceptionThrowingAlgorithm() {
            super("Test")
        }

        @Override
        protected OutputStream doCompress(OutputStream out) throws IOException {
            throw new IOException("Test Wrap OutputStream Exception")
        }

        @Override
        protected InputStream doDecompress(InputStream is) throws IOException {
            throw new IOException("Test Wrap InputStream Exception")
        }

        @Override
        protected byte[] doDecompress(byte[] payload) throws IOException {
            throw new IOException("Test Decompress Exception")
        }
    }
}
