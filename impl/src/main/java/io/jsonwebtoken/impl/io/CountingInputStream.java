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

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.atomic.AtomicLong;

public class CountingInputStream extends FilterInputStream {

    private final AtomicLong count = new AtomicLong(0);

    public CountingInputStream(InputStream in) {
        super(in);
    }

    public long getCount() {
        return count.get();
    }

    private void add(long n) {
        // n can be -1 for EOF, and 0 for no bytes read, so we only add if we actually read 1 or more bytes:
        if (n > 0) count.addAndGet(n);
    }

    @Override
    public int read() throws IOException {
        int next = super.read();
        add(next == Streams.EOF ? Streams.EOF : 1);
        return next;
    }

    @Override
    public int read(byte[] b) throws IOException {
        int n = super.read(b);
        add(n);
        return n;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        int n = super.read(b, off, len);
        add(n);
        return n;
    }

    @Override
    public long skip(long n) throws IOException {
        final long skipped = super.skip(n);
        add(skipped);
        return skipped;
    }
}
