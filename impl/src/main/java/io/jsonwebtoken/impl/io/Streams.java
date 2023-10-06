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

import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.lang.Strings;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Flushable;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.util.concurrent.Callable;

/**
 * @since 0.12.0
 */
public class Streams {

    /**
     * Represents the end-of-file (or stream).
     */
    public static final int EOF = -1;

    public static byte[] bytes(final InputStream in, String exmsg) {
        if (in instanceof BytesInputStream) {
            return ((BytesInputStream) in).getBytes();
        }
        // otherwise we have to copy over:
        ByteArrayOutputStream out = new ByteArrayOutputStream(8192);
        copy(in, out, new byte[8192], exmsg);
        return out.toByteArray();
    }

    public static InputStream of(byte[] bytes) {
        return new BytesInputStream(bytes);
    }

    public static InputStream of(CharSequence seq) {
        return of(Strings.utf8(seq));
    }

    public static Reader reader(byte[] bytes) {
        return reader(Streams.of(bytes));
    }

    public static Reader reader(InputStream in) {
        return new InputStreamReader(in, Strings.UTF_8);
    }

    public static Reader reader(CharSequence seq) {
        return new CharSequenceReader(seq);
    }

    public static void flush(Flushable... flushables) {
        Objects.nullSafeFlush(flushables);
    }

    /**
     * Copies bytes from a {@link InputStream} to an {@link OutputStream} using the specified {@code buffer}, avoiding
     * the need for a {@link BufferedInputStream}.
     *
     * @param inputStream  the {@link InputStream} to read.
     * @param outputStream the {@link OutputStream} to write.
     * @param buffer       the buffer to use for the copy
     * @return the number of bytes copied.
     * @throws IllegalArgumentException if the InputStream is {@code null}.
     * @throws IllegalArgumentException if the OutputStream is {@code null}.
     * @throws IOException              if an I/O error occurs.
     */
    public static long copy(final InputStream inputStream, final OutputStream outputStream, final byte[] buffer)
            throws IOException {
        Assert.notNull(inputStream, "inputStream cannot be null.");
        Assert.notNull(outputStream, "outputStream cannot be null.");
        Assert.notEmpty(buffer, "buffer cannot be null or empty.");
        long count = 0;
        int n = 0;
        while (n != EOF) {
            n = inputStream.read(buffer);
            if (n > 0) outputStream.write(buffer, 0, n);
            count += n;
        }
        return count;
    }

    public static long copy(final InputStream in, final OutputStream out, final byte[] buffer, final String exmsg) {
        return run(new Callable<Long>() {
            @Override
            public Long call() throws IOException {
                try {
                    reset(in);
                    return copy(in, out, buffer);
                } finally {
                    Objects.nullSafeFlush(out);
                    reset(in);
                }
            }
        }, exmsg);
    }

    public static void reset(final InputStream in) {
        if (in == null) return;
        Callable<Object> callable = new Callable<Object>() {
            @Override
            public Object call() {
                try {
                    in.reset();
                } catch (Throwable ignored) {
                }
                return null;
            }
        };
        try {
            callable.call();
        } catch (Throwable ignored) {
        }
    }

    public static void write(final OutputStream out, final byte[] bytes, String exMsg) {
        write(out, bytes, 0, Bytes.length(bytes), exMsg);
    }

    public static void write(final OutputStream out, final byte[] data, final int offset, final int len, String exMsg) {
        if (out == null || Bytes.isEmpty(data) || len <= 0) return;
        run(new Callable<Object>() {
            @Override
            public Object call() throws Exception {
                out.write(data, offset, len);
                return null;
            }
        }, exMsg);
    }

    public static void writeAndClose(final OutputStream out, final byte[] data, String exMsg) {
        try {
            write(out, data, exMsg);
        } finally {
            Objects.nullSafeClose(out);
        }
    }

    public static <V> V run(Callable<V> c, String ioExMsg) {
        Assert.hasText(ioExMsg, "IO Exception Message cannot be null or empty.");
        try {
            return c.call();
        } catch (Throwable t) {
            String msg = "IO failure: " + ioExMsg;
            if (!msg.endsWith(".")) {
                msg += ".";
            }
            msg += " Cause: " + t.getMessage();
            throw new io.jsonwebtoken.io.IOException(msg, t);
        }
    }
}
