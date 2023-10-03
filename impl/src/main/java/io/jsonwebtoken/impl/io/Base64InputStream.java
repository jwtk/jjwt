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

import java.io.InputStream;

/**
 * Provides Base64 encoding and decoding in a streaming fashion (unlimited size). When encoding the default lineLength
 * is 76 characters and the default lineEnding is CRLF, but these can be overridden by using the appropriate
 * constructor.
 * <p>
 * The default behavior of the Base64InputStream is to DECODE, whereas the default behavior of the Base64OutputStream
 * is to ENCODE, but this behavior can be overridden by using a different constructor.
 * </p>
 * <p>
 * This class implements section <cite>6.8. Base64 Content-Transfer-Encoding</cite> from RFC 2045 <cite>Multipurpose
 * Internet Mail Extensions (MIME) Part One: Format of Internet Message Bodies</cite> by Freed and Borenstein.
 * </p>
 * <p>
 * Since this class operates directly on byte streams, and not character streams, it is hard-coded to only encode/decode
 * character encodings which are compatible with the lower 127 ASCII chart (ISO-8859-1, Windows-1252, UTF-8, etc).
 * </p>
 * <p>
 * You can set the decoding behavior when the input bytes contain leftover trailing bits that cannot be created by a
 * valid encoding. These can be bits that are unused from the final character or entire characters. The default mode is
 * lenient decoding.
 * </p>
 * <ul>
 * <li>Lenient: Any trailing bits are composed into 8-bit bytes where possible. The remainder are discarded.
 * <li>Strict: The decoding will raise an {@link IllegalArgumentException} if trailing bits are not part of a valid
 * encoding. Any unused bits from the final character must be zero. Impossible counts of entire final characters are not
 * allowed.
 * </ul>
 * <p>
 * When strict decoding is enabled it is expected that the decoded bytes will be re-encoded to a byte array that matches
 * the original, i.e. no changes occur on the final character. This requires that the input bytes use the same padding
 * and alphabet as the encoder.
 * </p>
 *
 * @see <a href="http://www.ietf.org/rfc/rfc2045.txt">RFC 2045</a>
 * @since 0.12.0, copied from
 * <a href="https://github.com/apache/commons-codec/tree/585497f09b026f6602daf986723a554e051bdfe6">commons-codec
 * 585497f09b026f6602daf986723a554e051bdfe6</a>
 */
public class Base64InputStream extends BaseNCodecInputStream {

    /**
     * Creates a Base64InputStream such that all data read is Base64-decoded from the original provided InputStream.
     *
     * @param inputStream InputStream to wrap.
     */
    public Base64InputStream(final InputStream inputStream) {
        this(inputStream, false);
    }

    /**
     * Creates a Base64InputStream such that all data read is either Base64-encoded or Base64-decoded from the original
     * provided InputStream.
     *
     * @param inputStream InputStream to wrap.
     * @param doEncode    true if we should encode all data read from us, false if we should decode.
     */
    Base64InputStream(final InputStream inputStream, final boolean doEncode) {
        super(inputStream, new Base64Codec(0, BaseNCodec.CHUNK_SEPARATOR, false, CodecPolicy.STRICT), doEncode);
    }

//    /**
//     * Creates a Base64InputStream such that all data read is either Base64-encoded or Base64-decoded from the original
//     * provided InputStream.
//     *
//     * @param inputStream   InputStream to wrap.
//     * @param doEncode      true if we should encode all data read from us, false if we should decode.
//     * @param lineLength    If doEncode is true, each line of encoded data will contain lineLength characters (rounded down to
//     *                      the nearest multiple of 4). If lineLength &lt;= 0, the encoded data is not divided into lines. If
//     *                      doEncode is false, lineLength is ignored.
//     * @param lineSeparator If doEncode is true, each line of encoded data will be terminated with this byte sequence (e.g. \r\n).
//     *                      If lineLength &lt;= 0, the lineSeparator is not used. If doEncode is false lineSeparator is ignored.
//     */
//    Base64InputStream(final InputStream inputStream, final boolean doEncode, final int lineLength, final byte[] lineSeparator) {
//        super(inputStream, new Base64Codec(lineLength, lineSeparator), doEncode);
//    }
//
//    /**
//     * Creates a Base64InputStream such that all data read is either Base64-encoded or Base64-decoded from the original
//     * provided InputStream.
//     *
//     * @param inputStream    InputStream to wrap.
//     * @param doEncode       true if we should encode all data read from us, false if we should decode.
//     * @param lineLength     If doEncode is true, each line of encoded data will contain lineLength characters (rounded down to
//     *                       the nearest multiple of 4). If lineLength &lt;= 0, the encoded data is not divided into lines. If
//     *                       doEncode is false, lineLength is ignored.
//     * @param lineSeparator  If doEncode is true, each line of encoded data will be terminated with this byte sequence (e.g. \r\n).
//     *                       If lineLength &lt;= 0, the lineSeparator is not used. If doEncode is false lineSeparator is ignored.
//     * @param decodingPolicy The decoding policy.
//     * @since 1.15
//     */
//    Base64InputStream(final InputStream inputStream, final boolean doEncode, final int lineLength, final byte[] lineSeparator,
//                      final CodecPolicy decodingPolicy) {
//        super(inputStream, new Base64Codec(lineLength, lineSeparator, false, decodingPolicy), doEncode);
//    }
}
