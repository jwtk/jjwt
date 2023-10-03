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

import java.io.IOException;
import java.io.InputStream;

/**
 * @since 0.12.0, copied from
 * <a href="https://github.com/apache/commons-io/blob/3a17f5259b105e734c8adce1d06d68f29884d1bb/src/main/java/org/apache/commons/io/input/ClosedInputStream.java">
 * commons-io 3a17f5259b105e734c8adce1d06d68f29884d1bb</a>
 */
public final class ClosedInputStream extends InputStream {

    public static final ClosedInputStream INSTANCE = new ClosedInputStream();

    private ClosedInputStream() {
    }

    @Override
    public int read() throws IOException {
        return Streams.EOF;
    }
}
