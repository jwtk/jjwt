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

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.Jwks;
import io.jsonwebtoken.security.KeyOperation;
import io.jsonwebtoken.security.KeyOperationPolicy;
import io.jsonwebtoken.security.KeyOperationPolicyBuilder;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

public class DefaultKeyOperationPolicyBuilder implements KeyOperationPolicyBuilder {

    private final Map<String, KeyOperation> ops;
    private boolean allowUnrelated = false;

    public DefaultKeyOperationPolicyBuilder() {
        this.ops = new LinkedHashMap<>(Jwks.OP.get());
    }

    @Override
    public KeyOperationPolicyBuilder allowUnrelated(boolean allow) {
        this.allowUnrelated = allow;
        return this;
    }

    @Override
    public KeyOperationPolicyBuilder add(KeyOperation op) {
        if (op != null) {
            String id = Assert.hasText(op.getId(), "KeyOperation id cannot be null or empty.");
            this.ops.remove(id);
            this.ops.put(id, op);
        }
        return this;
    }

    @Override
    public KeyOperationPolicyBuilder add(Collection<KeyOperation> ops) {
        if (!Collections.isEmpty(ops)) {
            for (KeyOperation op : ops) {
                add(op);
            }
        }
        return this;
    }

    @Override
    public KeyOperationPolicy build() {
        return new DefaultKeyOperationPolicy(Collections.immutable(this.ops.values()), this.allowUnrelated);
    }
}
