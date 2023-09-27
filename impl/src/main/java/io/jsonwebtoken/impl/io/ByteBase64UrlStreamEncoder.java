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

import io.jsonwebtoken.io.Encoder;
import io.jsonwebtoken.io.EncodingException;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class ByteBase64UrlStreamEncoder implements Encoder<OutputStream, OutputStream> {

    private final Encoder<byte[], String> delegate;

    public ByteBase64UrlStreamEncoder(Encoder<byte[], String> delegate) {
        this.delegate = Assert.notNull(delegate, "delegate cannot be null.");
    }

    @Override
    public OutputStream encode(OutputStream outputStream) throws EncodingException {
        Assert.notNull(outputStream, "outputStream cannot be null.");
        return new TranslatingOutputStream(outputStream, delegate);
    }

    private static class TranslatingOutputStream extends FilteredOutputStream {

        private final OutputStream dst;
        private final Encoder<byte[], String> delegate;

        public TranslatingOutputStream(OutputStream dst, Encoder<byte[], String> delegate) {
            super(new ByteArrayOutputStream());
            this.dst = dst;
            this.delegate = delegate;
        }

        @Override
        public void close() throws IOException {
            byte[] data = ((ByteArrayOutputStream) out).toByteArray();
            String s = delegate.encode(data);
            dst.write(Strings.utf8(s));
            dst.flush();
            dst.close();
        }
    }
}
