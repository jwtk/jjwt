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

import io.jsonwebtoken.security.SecurityBuilder;

import java.security.Provider;
import java.security.SecureRandom;

abstract class AbstractSecurityBuilder<T, B extends SecurityBuilder<T, B>> implements SecurityBuilder<T, B> {

    protected Provider provider;
    protected SecureRandom random;

    @SuppressWarnings("unchecked")
    protected final B self() {
        return (B) this;
    }

    @Override
    public B provider(Provider provider) {
        this.provider = provider;
        return self();
    }

    @Override
    public B random(SecureRandom random) {
        this.random = random != null ? random : Randoms.secureRandom();
        return self();
    }
}
