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

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * A filter stream that delegates its calls to an internal delegate stream without changing behavior, but also providing
 * pre/post/error handling hooks.  It is useful as a base for extending and adding custom functionality.
 *
 * <p>It is an alternative base class to FilterInputStream to increase re-usability, because FilterInputStream changes
 * the methods being called, such as read(byte[]) to read(byte[], int, int).</p>
 *
 * @since 0.12.0, copied from
 * <a href="https://github.com/apache/commons-io/blob/3a17f5259b105e734c8adce1d06d68f29884d1bb/src/main/java/org/apache/commons/io/input/ProxyInputStream.java">
 * commons-io 3a17f5259b105e734c8adce1d06d68f29884d1bb</a>
 */
public abstract class FilteredInputStream extends FilterInputStream {

    /**
     * Constructs a new FilteredInputStream that delegates to the specified {@link InputStream}.
     *
     * @param in the InputStream to delegate to
     */
    public FilteredInputStream(final InputStream in) {
        super(in); // the delegate is stored in a protected superclass variable named 'in'
    }

    /**
     * Invoked by the read methods after the proxied call has returned
     * successfully. The number of bytes returned to the caller (or -1 if
     * the end of stream was reached) is given as an argument.
     * <p>
     * Subclasses can override this method to add common post-processing
     * functionality without having to override all the read methods.
     * The default implementation does nothing.
     * </p>
     * <p>
     * Note this method is <em>not</em> called from {@link #skip(long)} or
     * {@link #reset()}. You need to explicitly override those methods if
     * you want to add post-processing steps also to them.
     * </p>
     *
     * @param n number of bytes read, or -1 if the end of stream was reached
     * @throws IOException if the post-processing fails
     * @since 2.0
     */
    @SuppressWarnings({"unused", "RedundantThrows"}) // Possibly thrown from subclasses.
    protected void afterRead(final int n) throws IOException {
        // no-op
    }

    /**
     * Invokes the delegate's {@code available()} method.
     *
     * @return the number of available bytes
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public int available() throws IOException {
        try {
            return super.available();
        } catch (final Throwable t) {
            onThrowable(t);
            return 0;
        }
    }

    /**
     * Invoked by the read methods before the call is proxied. The number
     * of bytes that the caller wanted to read (1 for the {@link #read()}
     * method, buffer length for {@link #read(byte[])}, etc.) is given as
     * an argument.
     * <p>
     * Subclasses can override this method to add common pre-processing
     * functionality without having to override all the read methods.
     * The default implementation does nothing.
     * </p>
     * <p>
     * Note this method is <em>not</em> called from {@link #skip(long)} or
     * {@link #reset()}. You need to explicitly override those methods if
     * you want to add pre-processing steps also to them.
     * </p>
     *
     * @param n number of bytes that the caller asked to be read
     * @throws IOException if the pre-processing fails
     * @since 2.0
     */
    @SuppressWarnings({"unused", "RedundantThrows"}) // Possibly thrown from subclasses.
    protected void beforeRead(final int n) throws IOException {
        // no-op
    }

    /**
     * Invokes the delegate's {@code close()} method.
     *
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public void close() throws IOException {
        try {
            super.close();
        } catch (Throwable t) {
            onThrowable(t);
        }
    }

    /**
     * Handle any Throwable thrown; by default, throws the given exception.
     * <p>
     * This method provides a point to implement custom exception
     * handling. The default behavior is to re-throw the exception.
     * </p>
     *
     * @param t The IOException thrown
     * @throws IOException if an I/O error occurs.
     */
    protected void onThrowable(final Throwable t) throws IOException {
        if (t instanceof IOException) throw (IOException) t;
        throw new IOException("IO Exception: " + t.getMessage(), t);
    }

    /**
     * Invokes the delegate's {@code mark(int)} method.
     *
     * @param readlimit read ahead limit
     */
    @Override
    public synchronized void mark(final int readlimit) {
        in.mark(readlimit);
    }

    /**
     * Invokes the delegate's {@code markSupported()} method.
     *
     * @return true if mark is supported, otherwise false
     */
    @Override
    public boolean markSupported() {
        return in.markSupported();
    }

    /**
     * Invokes the delegate's {@code read()} method.
     *
     * @return the byte read or -1 if the end of stream
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public int read() throws IOException {
        try {
            beforeRead(1);
            final int b = in.read();
            afterRead(b != Streams.EOF ? 1 : Streams.EOF);
            return b;
        } catch (final Throwable t) {
            onThrowable(t);
            return Streams.EOF;
        }
    }

    /**
     * Invokes the delegate's {@code read(byte[])} method.
     *
     * @param bts the buffer to read the bytes into
     * @return the number of bytes read or EOF if the end of stream
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public int read(final byte[] bts) throws IOException {
        try {
            beforeRead(Bytes.length(bts));
            final int n = in.read(bts);
            afterRead(n);
            return n;
        } catch (final Throwable t) {
            onThrowable(t);
            return Streams.EOF;
        }
    }

    /**
     * Invokes the delegate's {@code read(byte[], int, int)} method.
     *
     * @param bts the buffer to read the bytes into
     * @param off The start offset
     * @param len The number of bytes to read
     * @return the number of bytes read or -1 if the end of stream
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public int read(final byte[] bts, final int off, final int len) throws IOException {
        try {
            beforeRead(len);
            final int n = in.read(bts, off, len);
            afterRead(n);
            return n;
        } catch (final Throwable t) {
            onThrowable(t);
            return Streams.EOF;
        }
    }

    /**
     * Invokes the delegate's {@code reset()} method.
     *
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public synchronized void reset() throws IOException {
        try {
            in.reset();
        } catch (final Throwable t) {
            onThrowable(t);
        }
    }

    /**
     * Invokes the delegate's {@code skip(long)} method.
     *
     * @param ln the number of bytes to skip
     * @return the actual number of bytes skipped
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public long skip(final long ln) throws IOException {
        try {
            return in.skip(ln);
        } catch (final Throwable t) {
            onThrowable(t);
            return 0;
        }
    }
}
