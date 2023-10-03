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

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * A Proxy stream which acts as expected, that is it passes the method
 * calls on to the proxied stream and doesn't change which methods are
 * being called. It is an alternative base class to FilterOutputStream
 * to increase reusability.
 * <p>
 * See the protected methods for ways in which a subclass can easily decorate
 * a stream with custom pre-, post- or error processing functionality.
 * </p>
 *
 * @since 0.12.0, copied from
 * <a href="https://github.com/apache/commons-io/blob/3a17f5259b105e734c8adce1d06d68f29884d1bb/src/main/java/org/apache/commons/io/output/ProxyOutputStream.java">
 * commons-io 3a17f5259b105e734c8adce1d06d68f29884d1bb</a>
 */
public class FilteredOutputStream extends FilterOutputStream {

    /**
     * Constructs a new ProxyOutputStream.
     *
     * @param out the OutputStream to delegate to
     */
    public FilteredOutputStream(final OutputStream out) {
        super(out); // the proxy is stored in a protected superclass variable named 'out'
    }

    /**
     * Invoked by the write methods after the proxied call has returned
     * successfully. The number of bytes written (1 for the
     * {@link #write(int)} method, buffer length for {@link #write(byte[])},
     * etc.) is given as an argument.
     * <p>
     * Subclasses can override this method to add common post-processing
     * functionality without having to override all the write methods.
     * The default implementation does nothing.
     *
     * @param n number of bytes written
     * @throws IOException if the post-processing fails
     * @since 2.0
     */
    @SuppressWarnings({"unused", "RedundantThrows"}) // Possibly thrown from subclasses.
    protected void afterWrite(final int n) throws IOException {
        // noop
    }

    /**
     * Invoked by the write methods before the call is proxied. The number
     * of bytes to be written (1 for the {@link #write(int)} method, buffer
     * length for {@link #write(byte[])}, etc.) is given as an argument.
     * <p>
     * Subclasses can override this method to add common pre-processing
     * functionality without having to override all the write methods.
     * The default implementation does nothing.
     *
     * @param n number of bytes to be written
     * @throws IOException if the pre-processing fails
     */
    @SuppressWarnings({"unused", "RedundantThrows"}) // Possibly thrown from subclasses.
    protected void beforeWrite(final int n) throws IOException {
        // noop
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
     * Invokes the delegate's {@code flush()} method.
     *
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public void flush() throws IOException {
        try {
            out.flush();
        } catch (final Throwable t) {
            onThrowable(t);
        }
    }

    /**
     * Handle any IOExceptions thrown.
     * <p>
     * This method provides a point to implement custom exception
     * handling. The default behavior is to re-throw the exception.
     *
     * @param t The Throwable thrown
     * @throws IOException if an I/O error occurs.
     */
    protected void onThrowable(final Throwable t) throws IOException {
        if (t instanceof IOException) throw (IOException) t;
        throw new IOException("IO Exception " + t.getMessage(), t);
    }

    /**
     * Invokes the delegate's {@code write(byte[])} method.
     *
     * @param bts the bytes to write
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public void write(final byte[] bts) throws IOException {
        try {
            final int len = Bytes.length(bts);
            beforeWrite(len);
            out.write(bts);
            afterWrite(len);
        } catch (final Throwable t) {
            onThrowable(t);
        }
    }

    /**
     * Invokes the delegate's {@code write(byte[])} method.
     *
     * @param bts the bytes to write
     * @param st  The start offset
     * @param end The number of bytes to write
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public void write(final byte[] bts, final int st, final int end) throws IOException {
        try {
            beforeWrite(end);
            out.write(bts, st, end);
            afterWrite(end);
        } catch (final Throwable t) {
            onThrowable(t);
        }
    }

    /**
     * Invokes the delegate's {@code write(int)} method.
     *
     * @param idx the byte to write
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public void write(final int idx) throws IOException {
        try {
            beforeWrite(1);
            out.write(idx);
            afterWrite(1);
        } catch (final Throwable t) {
            onThrowable(t);
        }
    }

}
