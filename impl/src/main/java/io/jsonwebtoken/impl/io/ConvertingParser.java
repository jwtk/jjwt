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

import io.jsonwebtoken.impl.lang.Converter;
import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.io.Parser;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Map;

public class ConvertingParser<T> implements Parser<T> {

    private final Function<InputStream, Map<String, ?>> deserializer;
    private final Converter<T, Object> converter;

    public ConvertingParser(Function<InputStream, Map<String, ?>> deserializer, Converter<T, Object> converter) {
        this.deserializer = Assert.notNull(deserializer, "Deserializer function cannot be null.");
        this.converter = Assert.notNull(converter, "Converter cannot be null.");
    }

    @Override
    public final T parse(String input) {
        Assert.hasText(input, "Parse input String cannot be null or empty.");
        InputStream in = new ByteArrayInputStream(Strings.utf8(input));
        return parse(in);
    }

    public final T parse(InputStream in) {
        Map<String, ?> m = this.deserializer.apply(in);
        return this.converter.applyFrom(m);
    }
}
