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
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.security.KeyOperation;
import io.jsonwebtoken.security.KeyOperationPolicy;

import java.util.Collection;

final class DefaultKeyOperationPolicy implements KeyOperationPolicy {

    private final Collection<KeyOperation> ops;

    private final boolean allowUnrelated;

    DefaultKeyOperationPolicy(Collection<KeyOperation> ops, boolean allowUnrelated) {
        Assert.notEmpty(ops, "KeyOperation collection cannot be null or empty.");
        this.ops = Collections.immutable(ops);
        this.allowUnrelated = allowUnrelated;
    }

    @Override
    public Collection<KeyOperation> getOperations() {
        return this.ops;
    }

    @Override
    public void validate(Collection<KeyOperation> ops) {
        if (allowUnrelated || Collections.isEmpty(ops)) return;
        for (KeyOperation operation : ops) {
            for (KeyOperation inner : ops) {
                if (!operation.isRelated(inner)) {
                    String msg = "Unrelated key operations are not allowed. KeyOperation [" + inner +
                            "] is unrelated to [" + operation + "].";
                    throw new IllegalArgumentException(msg);
                }
            }
        }
    }

    @Override
    public int hashCode() {
        int hash = Boolean.valueOf(this.allowUnrelated).hashCode();
        KeyOperation[] ops = this.ops.toArray(new KeyOperation[0]);
        hash = 31 * hash + Objects.nullSafeHashCode((Object[]) ops);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (!(obj instanceof DefaultKeyOperationPolicy)) {
            return false;
        }
        DefaultKeyOperationPolicy other = (DefaultKeyOperationPolicy) obj;
        return this.allowUnrelated == other.allowUnrelated &&
                Collections.size(this.ops) == Collections.size(other.ops) &&
                this.ops.containsAll(other.ops);
    }
}
