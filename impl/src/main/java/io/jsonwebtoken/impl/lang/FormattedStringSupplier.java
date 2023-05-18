/*
 * Copyright (C) 2022 jsonwebtoken.io
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
import io.jsonwebtoken.lang.Supplier;

public class FormattedStringSupplier implements Supplier<String> {

    private final String msg;

    private final Object[] args;

    public FormattedStringSupplier(String msg, Object[] args) {
        this.msg = Assert.hasText(msg, "Message cannot be null or empty.");
        this.args = Assert.notEmpty(args, "Arguments cannot be null or empty.");
    }

    @Override
    public String get() {
        return String.format(this.msg, this.args);
    }
}
