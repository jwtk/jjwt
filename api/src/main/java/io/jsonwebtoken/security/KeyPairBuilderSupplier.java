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
package io.jsonwebtoken.security;

import java.security.KeyPair;

/**
 * Interface implemented by components that support building/creating new {@link KeyPair}s suitable for use with their
 * associated cryptographic algorithm implementation.
 *
 * @see #keyPair()
 * @see KeyPairBuilder
 * @since JJWT_RELEASE_VERSION
 */
public interface KeyPairBuilderSupplier {

    /**
     * Returns a new {@link KeyPairBuilder} that will create new secure-random {@link KeyPair}s with a length and
     * parameters sufficient for use with the component's associated cryptographic algorithm.
     *
     * @return a new {@link KeyPairBuilder} that will create new secure-random {@link KeyPair}s with a length and
     * parameters sufficient for use with the component's associated cryptographic algorithm.
     */
    KeyPairBuilder keyPair();
}
