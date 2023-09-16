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

import io.jsonwebtoken.impl.io.AbstractParserBuilder;
import io.jsonwebtoken.io.ParserBuilder;
import io.jsonwebtoken.security.KeyOperationPolicied;
import io.jsonwebtoken.security.KeyOperationPolicy;

abstract class AbstractJwkParserBuilder<T, B extends ParserBuilder<T, B> & KeyOperationPolicied<B>>
        extends AbstractParserBuilder<T, B> implements KeyOperationPolicied<B> {

    protected KeyOperationPolicy operationPolicy = AbstractJwkBuilder.DEFAULT_OPERATION_POLICY;

    @Override
    public B operationPolicy(KeyOperationPolicy policy) throws IllegalArgumentException {
        this.operationPolicy = policy;
        return self();
    }
}
