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
package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.KeyOperation;
import io.jsonwebtoken.security.KeyOperationBuilder;

import java.util.LinkedHashSet;
import java.util.Set;

public class DefaultKeyOperationBuilder implements KeyOperationBuilder {

    private String id;
    private String description;
    private final Set<String> related = new LinkedHashSet<>();

    @Override
    public KeyOperationBuilder id(String id) {
        this.id = id;
        return this;
    }

    @Override
    public KeyOperationBuilder description(String description) {
        this.description = description;
        return this;
    }

    @Override
    public KeyOperationBuilder related(String related) {
        if (Strings.hasText(related)) {
            this.related.add(related);
        }
        return this;
    }

    @Override
    public KeyOperation build() {
        return new DefaultKeyOperation(this.id, this.description, this.related);
    }
}
