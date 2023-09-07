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

import io.jsonwebtoken.lang.Builder;

import java.util.Collection;

/**
 * A {@code KeyOperationBuilder} produces {@link KeyOperation} instances that may be added to a JWK's
 * {@link JwkBuilder#operations(Collection) key operations} parameter. This is primarily only useful for creating
 * custom (non-standard) {@code KeyOperation}s, as all standard ones are available already via the
 * {@link Jwks.OP} registry singleton.
 *
 * @since JJWT_RELEASE_VERSION
 */
public interface KeyOperationBuilder extends Builder<KeyOperation> {

    /**
     * Sets the CaSe-SeNsItIvE {@link KeyOperation#getId() id} expected to be unique compared to all other
     * {@code KeyOperation}s.
     *
     * @param id the key operation id
     * @return the builder for method chaining
     */
    KeyOperationBuilder id(String id);

    /**
     * Sets the key operation {@link KeyOperation#getDescription() description}.
     *
     * @param description the key operation description
     * @return the builder for method chaining
     */
    KeyOperationBuilder description(String description);

//    KeyOperationBuilder related(String related);
//
//    KeyOperationBuilder related(Collection<String> related);
}
