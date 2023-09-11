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
package io.jsonwebtoken.security;

import io.jsonwebtoken.lang.MapMutator;

import java.util.Collection;

public interface JwkSetBuilder extends MapMutator<String, Object, JwkSetBuilder>,
        SecurityBuilder<JwkSet, JwkSetBuilder>, KeyOperationPolicied<JwkSetBuilder> {

    JwkSetBuilder add(Jwk<?> jwk);

    JwkSetBuilder add(Collection<Jwk<?>> c);

    JwkSetBuilder keys(Collection<Jwk<?>> c);

}
