/*
 * Copyright © 2022 jsonwebtoken.io
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
package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.lang.Assert;

public class FormattedStringFunction<T> implements Function<T, String> {

    private final String msg;

    public FormattedStringFunction(String msg) {
        this.msg = Assert.hasText(msg, "msg argument cannot be null or empty.");
    }

    @Override
    public String apply(T arg) {
        return String.format(msg, arg);
    }
}
