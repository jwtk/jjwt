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

import io.jsonwebtoken.impl.lang.DefaultCollectionMutator;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.Jwks;
import io.jsonwebtoken.security.KeyOperation;
import io.jsonwebtoken.security.KeyOperationPolicy;
import io.jsonwebtoken.security.KeyOperationPolicyBuilder;

public class DefaultKeyOperationPolicyBuilder extends DefaultCollectionMutator<KeyOperation, KeyOperationPolicyBuilder>
        implements KeyOperationPolicyBuilder {

    private boolean unrelated = false;

    public DefaultKeyOperationPolicyBuilder() {
        super(Jwks.OP.get().values());
    }

    @Override
    public KeyOperationPolicyBuilder unrelated() {
        this.unrelated = true;
        return this;
    }

    @Override
    public KeyOperationPolicy build() {
        return new DefaultKeyOperationPolicy(Collections.immutable(getCollection()), this.unrelated);
    }
}
