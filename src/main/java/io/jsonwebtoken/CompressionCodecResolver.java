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
package io.jsonwebtoken;

/**
 * Resolves "calg" header to an implementation of CompressionCodec.
 *
 * @since 0.5.2
 */
public interface CompressionCodecResolver {
    /**
     * Examines the header and returns a CompressionCodec if it finds one that it recognizes.
     * @param header of the JWT
     * @return CompressionCodec matching the "calg" header, or null if there is no "calg" header.
     */
    CompressionCodec resolveCompressionCodec(Header header);

}
