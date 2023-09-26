/*
 * Copyright (C) 2019 jsonwebtoken.io
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

/**
 * Yet Another GZIP CompressionCodec.  This codec has the same name as the Official GZIP impl. The IdLocator will NOT resolve this class.
 */
class YagCompressionCodec implements CompressionCodec {

    @Override
    String getId() {
        return GzipCompressionAlgorithm.ID
    }

    @Override
    String getAlgorithmName() {
        return getId()
    }

    @Override
    byte[] compress(byte[] content) throws CompressionException {
        return new byte[0]
    }

    @Override
    byte[] decompress(byte[] compressed) throws CompressionException {
        return new byte[0]
    }

    @Override
    OutputStream compress(OutputStream out) throws CompressionException {
        return out
    }

    @Override
    InputStream decompress(InputStream inputStream) throws CompressionException {
        return inputStream
    }
}