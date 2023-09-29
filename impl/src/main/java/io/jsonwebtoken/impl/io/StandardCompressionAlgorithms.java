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
package io.jsonwebtoken.impl.io;

import io.jsonwebtoken.impl.compression.DeflateCompressionAlgorithm;
import io.jsonwebtoken.impl.compression.GzipCompressionAlgorithm;
import io.jsonwebtoken.impl.lang.IdRegistry;
import io.jsonwebtoken.io.CompressionAlgorithm;
import io.jsonwebtoken.lang.Collections;

@SuppressWarnings("unused") // used via reflection in io.jsonwebtoken.Jwts.ZIP
public final class StandardCompressionAlgorithms extends IdRegistry<CompressionAlgorithm> {

    public static final String NAME = "Compression Algorithm";

    public StandardCompressionAlgorithms() {
        super(NAME, Collections.<CompressionAlgorithm>of(
                new DeflateCompressionAlgorithm(),
                new GzipCompressionAlgorithm()
        ));
    }
}
