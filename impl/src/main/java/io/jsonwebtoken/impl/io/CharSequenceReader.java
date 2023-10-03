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

import java.io.Reader;
import java.io.Serializable;
import java.util.Objects;

/**
 * {@link Reader} implementation that can read from String, StringBuffer, StringBuilder or CharBuffer.
 *
 * <p>
 * <strong>Note:</strong> Supports {@link #mark(int)} and {@link #reset()}.
 * </p>
 *
 * @since 0.12.0, copied from commons-io
 * <a href="https://github.com/apache/commons-io/blob/e67946c81a55069dcd32dd588faa57dd1532455f/src/main/java/org/apache/commons/io/input/CharSequenceInputStream.java">2.14.0</a>
 */
public class CharSequenceReader extends Reader implements Serializable {

    private static final long serialVersionUID = 3724187752191401220L;
    private final CharSequence charSequence;
    private int idx;
    private int mark;

    /**
     * The start index in the character sequence, inclusive.
     * <p>
     * When de-serializing a CharSequenceReader that was serialized before
     * this fields was added, this field will be initialized to 0, which
     * gives the same behavior as before: start reading from the start.
     * </p>
     *
     * @see #start()
     * @since 2.7
     */
    private final int start;

    /**
     * The end index in the character sequence, exclusive.
     * <p>
     * When de-serializing a CharSequenceReader that was serialized before
     * this fields was added, this field will be initialized to {@code null},
     * which gives the same behavior as before: stop reading at the
     * CharSequence's length.
     * If this field was an int instead, it would be initialized to 0 when the
     * CharSequenceReader is de-serialized, causing it to not return any
     * characters at all.
     * </p>
     *
     * @see #end()
     * @since 2.7
     */
    private final Integer end;

    /**
     * Constructs a new instance with the specified character sequence.
     *
     * @param charSequence The character sequence, may be {@code null}
     */
    public CharSequenceReader(final CharSequence charSequence) {
        this(charSequence, 0);
    }

    /**
     * Constructs a new instance with a portion of the specified character sequence.
     * <p>
     * The start index is not strictly enforced to be within the bounds of the
     * character sequence. This allows the character sequence to grow or shrink
     * in size without risking any {@link IndexOutOfBoundsException} to be thrown.
     * Instead, if the character sequence grows smaller than the start index, this
     * instance will act as if all characters have been read.
     * </p>
     *
     * @param charSequence The character sequence, may be {@code null}
     * @param start        The start index in the character sequence, inclusive
     * @throws IllegalArgumentException if the start index is negative
     */
    public CharSequenceReader(final CharSequence charSequence, final int start) {
        this(charSequence, start, Integer.MAX_VALUE);
    }

    /**
     * Constructs a new instance with a portion of the specified character sequence.
     * <p>
     * The start and end indexes are not strictly enforced to be within the bounds
     * of the character sequence. This allows the character sequence to grow or shrink
     * in size without risking any {@link IndexOutOfBoundsException} to be thrown.
     * Instead, if the character sequence grows smaller than the start index, this
     * instance will act as if all characters have been read; if the character sequence
     * grows smaller than the end, this instance will use the actual character sequence
     * length.
     * </p>
     *
     * @param charSequence The character sequence, may be {@code null}
     * @param start        The start index in the character sequence, inclusive
     * @param end          The end index in the character sequence, exclusive
     * @throws IllegalArgumentException if the start index is negative, or if the end index is smaller than the start index
     */
    public CharSequenceReader(final CharSequence charSequence, final int start, final int end) {
        if (start < 0) {
            throw new IllegalArgumentException("Start index is less than zero: " + start);
        }
        if (end < start) {
            throw new IllegalArgumentException("End index is less than start " + start + ": " + end);
        }
        // Don't check the start and end indexes against the CharSequence,
        // to let it grow and shrink without breaking existing behavior.

        this.charSequence = charSequence != null ? charSequence : "";
        this.start = start;
        this.end = end;

        this.idx = start;
        this.mark = start;
    }

    /**
     * Close resets the file back to the start and removes any marked position.
     */
    @Override
    public void close() {
        idx = start;
        mark = start;
    }

    /**
     * Returns the index in the character sequence to end reading at, taking into account its length.
     *
     * @return The end index in the character sequence (exclusive).
     */
    private int end() {
        /*
         * end == null for de-serialized instances that were serialized before start and end were added.
         * Use Integer.MAX_VALUE to get the same behavior as before - use the entire CharSequence.
         */
        return Math.min(charSequence.length(), end == null ? Integer.MAX_VALUE : end);
    }

    /**
     * Mark the current position.
     *
     * @param readAheadLimit ignored
     */
    @Override
    public void mark(final int readAheadLimit) {
        mark = idx;
    }

    /**
     * Mark is supported (returns true).
     *
     * @return {@code true}
     */
    @Override
    public boolean markSupported() {
        return true;
    }

    /**
     * Read a single character.
     *
     * @return the next character from the character sequence
     * or -1 if the end has been reached.
     */
    @Override
    public int read() {
        if (idx >= end()) {
            return Streams.EOF;
        }
        return charSequence.charAt(idx++);
    }

    /**
     * Read the specified number of characters into the array.
     *
     * @param array  The array to store the characters in
     * @param offset The starting position in the array to store
     * @param length The maximum number of characters to read
     * @return The number of characters read or -1 if there are
     * no more
     */
    @Override
    public int read(final char[] array, final int offset, final int length) {
        if (idx >= end()) {
            return Streams.EOF;
        }
        Objects.requireNonNull(array, "array");
        if (length < 0 || offset < 0 || offset + length > array.length) {
            throw new IndexOutOfBoundsException("Array Size=" + array.length +
                    ", offset=" + offset + ", length=" + length);
        }

        if (charSequence instanceof String) {
            final int count = Math.min(length, end() - idx);
            ((String) charSequence).getChars(idx, idx + count, array, offset);
            idx += count;
            return count;
        }
        if (charSequence instanceof StringBuilder) {
            final int count = Math.min(length, end() - idx);
            ((StringBuilder) charSequence).getChars(idx, idx + count, array, offset);
            idx += count;
            return count;
        }
        if (charSequence instanceof StringBuffer) {
            final int count = Math.min(length, end() - idx);
            ((StringBuffer) charSequence).getChars(idx, idx + count, array, offset);
            idx += count;
            return count;
        }

        int count = 0;
        for (int i = 0; i < length; i++) {
            final int c = read();
            if (c == Streams.EOF) {
                return count;
            }
            array[offset + i] = (char) c;
            count++;
        }
        return count;
    }

    /**
     * Tells whether this stream is ready to be read.
     *
     * @return {@code true} if more characters from the character sequence are available, or {@code false} otherwise.
     */
    @Override
    public boolean ready() {
        return idx < end();
    }

    /**
     * Reset the reader to the last marked position (or the beginning if
     * mark has not been called).
     */
    @Override
    public void reset() {
        idx = mark;
    }

    /**
     * Skip the specified number of characters.
     *
     * @param n The number of characters to skip
     * @return The actual number of characters skipped
     */
    @Override
    public long skip(final long n) {
        if (n < 0) {
            throw new IllegalArgumentException("Number of characters to skip is less than zero: " + n);
        }
        if (idx >= end()) {
            return 0;
        }
        final int dest = (int) Math.min(end(), idx + n);
        final int count = dest - idx;
        idx = dest;
        return count;
    }

    /**
     * Returns the index in the character sequence to start reading from, taking into account its length.
     *
     * @return The start index in the character sequence (inclusive).
     */
    private int start() {
        return Math.min(charSequence.length(), start);
    }

    /**
     * Return a String representation of the underlying
     * character sequence.
     *
     * @return The contents of the character sequence
     */
    @Override
    public String toString() {
        final CharSequence subSequence = charSequence.subSequence(start(), end());
        return subSequence.toString();
    }
}
