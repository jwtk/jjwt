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

import io.jsonwebtoken.impl.lang.Converter;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Registry;
import io.jsonwebtoken.security.Jwks;
import io.jsonwebtoken.security.KeyOperation;

final class KeyOperationConverter implements Converter<KeyOperation, Object> {

    static final Converter<KeyOperation, Object> DEFAULT = new KeyOperationConverter(Jwks.OP.get());

    private final Registry<String, KeyOperation> registry;

    KeyOperationConverter(Registry<String, KeyOperation> registry) {
        this.registry = Assert.notEmpty(registry, "KeyOperation registry cannot be null or empty.");
    }

    @Override
    public String applyTo(KeyOperation operation) {
        Assert.notNull(operation, "KeyOperation cannot be null.");
        return operation.getId();
    }

    @Override
    public KeyOperation applyFrom(Object o) {
        if (o instanceof KeyOperation) {
            return (KeyOperation) o;
        }
        String id = Assert.isInstanceOf(String.class, o, "Argument must be a KeyOperation or String.");
        Assert.hasText(id, "KeyOperation string value cannot be null or empty.");
        KeyOperation keyOp = this.registry.get(id);
        return keyOp != null ? keyOp : Jwks.OP.builder().id(id).build(); // custom operations are allowed
    }
}
