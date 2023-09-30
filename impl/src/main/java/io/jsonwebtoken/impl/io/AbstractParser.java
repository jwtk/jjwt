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

import io.jsonwebtoken.io.Parser;
import io.jsonwebtoken.lang.Assert;

import java.io.InputStream;
import java.io.Reader;

public abstract class AbstractParser<T> implements Parser<T> {

    @Override
    public final T parse(CharSequence input) {
        Assert.hasText(input, "CharSequence cannot be null or empty.");
        return parse(input, 0, input.length());
    }

    @Override
    public T parse(CharSequence input, int start, int end) {
        Assert.hasText(input, "CharSequence cannot be null or empty.");
        Reader reader = new CharSequenceReader(input, start, end);
        return parse(reader);
    }

    @Override
    public final T parse(InputStream in) {
        Assert.notNull(in, "InputStream cannot be null.");
        Reader reader = Streams.reader(in);
        return parse(reader);
    }
}
