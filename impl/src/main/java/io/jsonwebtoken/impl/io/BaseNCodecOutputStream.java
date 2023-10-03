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

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Objects;

/**
 * Abstract superclass for Base-N output streams.
 * <p>
 * To write the EOF marker without closing the stream, call {@link #eof()} or use an <a
 * href="https://commons.apache.org/proper/commons-io/">Apache Commons IO</a> <a href=
 * "https://commons.apache.org/proper/commons-io/apidocs/org/apache/commons/io/output/CloseShieldOutputStream.html"
 * >CloseShieldOutputStream</a>.
 * </p>
 *
 * @since 0.12.0, copied from
 * <a href="https://github.com/apache/commons-codec/tree/585497f09b026f6602daf986723a554e051bdfe6">commons-codec
 * 585497f09b026f6602daf986723a554e051bdfe6</a>
 */
class BaseNCodecOutputStream extends FilterOutputStream {

    private final boolean doEncode;

    private final BaseNCodec baseNCodec;

    private final byte[] singleByte = new byte[1];

    private final BaseNCodec.Context context = new BaseNCodec.Context();

    /**
     * TODO should this be protected?
     *
     * @param outputStream the underlying output or null.
     * @param basedCodec   a BaseNCodec.
     * @param doEncode     true to encode, false to decode, TODO should be an enum?
     */
    BaseNCodecOutputStream(final OutputStream outputStream, final BaseNCodec basedCodec, final boolean doEncode) {
        super(outputStream);
        this.baseNCodec = basedCodec;
        this.doEncode = doEncode;
    }

    /**
     * Closes this output stream and releases any system resources associated with the stream.
     * <p>
     * To write the EOF marker without closing the stream, call {@link #eof()} or use an
     * <a href="https://commons.apache.org/proper/commons-io/">Apache Commons IO</a> <a href=
     * "https://commons.apache.org/proper/commons-io/apidocs/org/apache/commons/io/output/CloseShieldOutputStream.html"
     * >CloseShieldOutputStream</a>.
     * </p>
     *
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public void close() throws IOException {
        eof();
        flush();
        out.close();
    }

    /**
     * Writes EOF.
     *
     * @since 1.11
     */
    public void eof() {
        // Notify encoder of EOF (-1).
        if (doEncode) {
            baseNCodec.encode(singleByte, 0, BaseNCodec.EOF, context);
        } else {
            baseNCodec.decode(singleByte, 0, BaseNCodec.EOF, context);
        }
    }

    /**
     * Flushes this output stream and forces any buffered output bytes to be written out to the stream.
     *
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public void flush() throws IOException {
        flush(true);
    }

    /**
     * Flushes this output stream and forces any buffered output bytes to be written out to the stream. If propagate is
     * true, the wrapped stream will also be flushed.
     *
     * @param propagate boolean flag to indicate whether the wrapped OutputStream should also be flushed.
     * @throws IOException if an I/O error occurs.
     */
    private void flush(final boolean propagate) throws IOException {
        final int avail = baseNCodec.available(context);
        if (avail > 0) {
            final byte[] buf = new byte[avail];
            final int c = baseNCodec.readResults(buf, 0, avail, context);
            if (c > 0) {
                out.write(buf, 0, c);
            }
        }
        if (propagate) {
            out.flush();
        }
    }

    /**
     * Returns true if decoding behavior is strict. Decoding will raise an
     * {@link IllegalArgumentException} if trailing bits are not part of a valid encoding.
     *
     * <p>
     * The default is false for lenient encoding. Decoding will compose trailing bits
     * into 8-bit bytes and discard the remainder.
     * </p>
     *
     * @return true if using strict decoding
     * @since 1.15
     */
    public boolean isStrictDecoding() {
        return baseNCodec.isStrictDecoding();
    }

    /**
     * Writes {@code len} bytes from the specified {@code b} array starting at {@code offset} to this
     * output stream.
     *
     * @param array  source byte array
     * @param offset where to start reading the bytes
     * @param len    maximum number of bytes to write
     * @throws IOException               if an I/O error occurs.
     * @throws NullPointerException      if the byte array parameter is null
     * @throws IndexOutOfBoundsException if offset, len or buffer size are invalid
     */
    @Override
    public void write(final byte[] array, final int offset, final int len) throws IOException {
        Objects.requireNonNull(array, "array");
        if (offset < 0 || len < 0) {
            throw new IndexOutOfBoundsException();
        }
        if (offset > array.length || offset + len > array.length) {
            throw new IndexOutOfBoundsException();
        }
        if (len > 0) {
            if (doEncode) {
                baseNCodec.encode(array, offset, len, context);
            } else {
                baseNCodec.decode(array, offset, len, context);
            }
            flush(false);
        }
    }

    /**
     * Writes the specified {@code byte} to this output stream.
     *
     * @param i source byte
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public void write(final int i) throws IOException {
        singleByte[0] = (byte) i;
        write(singleByte, 0, 1);
    }

}
