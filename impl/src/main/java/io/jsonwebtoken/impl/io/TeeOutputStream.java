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

import io.jsonwebtoken.lang.Assert;

import java.io.IOException;
import java.io.OutputStream;

/**
 * @since 0.12.0
 */
public class TeeOutputStream extends FilteredOutputStream {

    private final OutputStream other;

    public TeeOutputStream(OutputStream one, OutputStream two) {
        super(one);
        this.other = Assert.notNull(two, "Second OutputStream cannot be null.");
    }

    @Override
    public void close() throws IOException {
        try {
            super.close();
        } finally {
            this.other.close();
        }
    }

    @Override
    public void flush() throws IOException {
        super.flush();
        this.other.flush();
    }

    @Override
    public void write(byte[] bts) throws IOException {
        super.write(bts);
        this.other.write(bts);
    }

    @Override
    public void write(byte[] bts, int st, int end) throws IOException {
        super.write(bts, st, end);
        this.other.write(bts, st, end);
    }

    @Override
    public void write(int idx) throws IOException {
        super.write(idx);
        this.other.write(idx);
    }
}
