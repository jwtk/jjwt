/*
 * Copyright (C) 2021 jsonwebtoken.io
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
package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.SecretKeyBuilder

import javax.crypto.SecretKey
import java.security.Provider
import java.security.SecureRandom

class FixedSecretKeyBuilder implements SecretKeyBuilder {

    final SecretKey key

    FixedSecretKeyBuilder(SecretKey key) {
        this.key = key
    }

    @Override
    SecretKey build() {
        return this.key
    }

    @Override
    SecretKeyBuilder provider(Provider provider) {
        return this
    }

    @Override
    SecretKeyBuilder random(SecureRandom random) {
        return this
    }
}
