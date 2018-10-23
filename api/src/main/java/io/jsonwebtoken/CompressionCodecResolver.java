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
 * Looks for a JWT {@code zip} header, and if found, returns the corresponding {@link CompressionCodec} the parser
 * can use to decompress the JWT body.
 *
 * <p>JJWT's default {@link JwtParser} implementation supports both the
 * {@link CompressionCodecs#DEFLATE DEFLATE}
 * and {@link CompressionCodecs#GZIP GZIP} algorithms by default - you do not need to
 * specify a {@code CompressionCodecResolver} in these cases.</p>
 *
 * <p>However, if you want to use a compression algorithm other than {@code DEF} or {@code GZIP}, you must implement
 * your own {@link CompressionCodecResolver} and specify that when
 * {@link io.jsonwebtoken.JwtBuilder#compressWith(CompressionCodec) building} and
 * {@link io.jsonwebtoken.JwtParser#setCompressionCodecResolver(CompressionCodecResolver) parsing} JWTs.</p>
 *
 * @since 0.6.0
 */
public interface CompressionCodecResolver {

    /**
     * Looks for a JWT {@code zip} header, and if found, returns the corresponding {@link CompressionCodec} the parser
     * can use to decompress the JWT body.
     *
     * @param header of the JWT
     * @return CompressionCodec matching the {@code zip} header, or null if there is no {@code zip} header.
     * @throws CompressionException if a {@code zip} header value is found and not supported.
     */
    CompressionCodec resolveCompressionCodec(Header header) throws CompressionException;

}
