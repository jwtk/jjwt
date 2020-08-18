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

import java.security.Provider;
import java.security.SecureRandom;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface SecurityRequest {

    /**
     * Returns the JCA provider that should be used for cryptographic operations during the request or
     * {@code null} if the JCA subsystem preferred provider should be used.
     *
     * @return the JCA provider that should be used for cryptographic operations during the request or
     * {@code null} if the JCA subsystem preferred provider should be used.
     */
    Provider getProvider();

    /**
     * Returns the {@code SecureRandom} to use when performing cryptographic operations during the request, or
     * {@code null} if a default {@link SecureRandom} should be used.
     *
     * @return the {@code SecureRandom} to use when performing cryptographic operations during the request, or
     * {@code null} if a default {@link SecureRandom} should be used.
     */
    SecureRandom getSecureRandom();
}
