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

import io.jsonwebtoken.CompressionCodec
import io.jsonwebtoken.CompressionException
import org.junit.Test

/**
 * @since 0.6.0
 */
class AbstractCompressionCodecTest {
    static class ExceptionThrowingCodec extends AbstractCompressionCodec {

        @Override
        protected byte[] doCompress(byte[] payload) throws IOException {
            throw new IOException("Test Exception")
        }

        @Override
        String getAlgorithmName() {
            return "Test"
        }

        @Override
        protected byte[] doDecompress(byte[] payload) throws IOException {
            throw new IOException("Test Decompress Exception");
        }
    }

    @Test(expected = CompressionException.class)
    void testCompressWithException() {
        CompressionCodec codecUT = new ExceptionThrowingCodec();
        codecUT.compress(new byte[0]);
    }

    @Test(expected = CompressionException.class)
    void testDecompressWithException() {
        CompressionCodec codecUT = new ExceptionThrowingCodec();
        codecUT.decompress(new byte[0]);
    }
}
