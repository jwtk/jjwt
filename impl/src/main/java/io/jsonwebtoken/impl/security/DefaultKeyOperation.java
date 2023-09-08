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
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.KeyOperation;

import java.util.Set;

final class DefaultKeyOperation implements KeyOperation {

    private static final String CUSTOM_DESCRIPTION = "Custom key operation";

    static final KeyOperation SIGN = of("sign", "Compute digital signature or MAC", "verify");
    static final KeyOperation VERIFY = of("verify", "Verify digital signature or MAC", "sign");
    static final KeyOperation ENCRYPT = of("encrypt", "Encrypt content", "decrypt");
    static final KeyOperation DECRYPT =
            of("decrypt", "Decrypt content and validate decryption, if applicable", "encrypt");
    static final KeyOperation WRAP = of("wrapKey", "Encrypt key", "unwrapKey");
    static final KeyOperation UNWRAP =
            of("unwrapKey", "Decrypt key and validate decryption, if applicable", "wrapKey");
    static final KeyOperation DERIVE_KEY = of("deriveKey", "Derive key", null);
    static final KeyOperation DERIVE_BITS =
            of("deriveBits", "Derive bits not to be used as a key", null);

    final String id;
    final String description;
    final Set<String> related;

    static KeyOperation of(String id, String description, String related) {
        return new DefaultKeyOperation(id, description, Collections.setOf(related));
    }

    DefaultKeyOperation(String id) {
        this(id, null, null);
    }

    DefaultKeyOperation(String id, String description, Set<String> related) {
        this.id = Assert.hasText(id, "id cannot be null or empty.");
        this.description = Strings.hasText(description) ? description : CUSTOM_DESCRIPTION;
        this.related = related != null ? Collections.immutable(related) : Collections.<String>emptySet();
    }

    @Override
    public String getId() {
        return this.id;
    }

    @Override
    public String getDescription() {
        return this.description;
    }

    @Override
    public boolean isRelated(KeyOperation operation) {
        return equals(operation) || (operation != null && this.related.contains(operation.getId()));
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        return obj == this ||
                (obj instanceof KeyOperation && this.id.equals(((KeyOperation) obj).getId()));
    }

    @Override
    public String toString() {
        return "'" + this.id + "' (" + this.description + ")";
    }
}
