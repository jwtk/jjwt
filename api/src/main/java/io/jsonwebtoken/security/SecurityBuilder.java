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

import io.jsonwebtoken.lang.Builder;

import java.security.Provider;
import java.security.SecureRandom;

/**
 * A Security-specific {@link Builder} that allows configuration of common JCA API parameters that might be used
 * during instance creation, such as a {@link java.security.Provider} or {@link java.security.SecureRandom}.
 *
 * @param <T> The type of object that will be created each time {@link #build()} is invoked.
 * @see #provider(Provider)
 * @see #random(SecureRandom)
 * @since JJWT_RELEASE_VERSION
 */
public interface SecurityBuilder<T, B extends SecurityBuilder<T, B>> extends Builder<T> {

    /**
     * Sets the JCA Security {@link Provider} to use if necessary when calling {@link #build()}.  This is an optional
     * property - if not specified, the default JCA Provider will be used.
     *
     * @param provider the JCA Security Provider instance to use if necessary when building the new instance.
     * @return the builder for method chaining.
     */
    B provider(Provider provider);

    /**
     * Sets the {@link SecureRandom} to use if necessary when calling {@link #build()}.  This is an optional property
     * - if not specified and one is required, a default {@code SecureRandom} will be used.
     *
     * @param random the {@link SecureRandom} instance to use if necessary when building the new instance.
     * @return the builder for method chaining.
     */
    B random(SecureRandom random);
}
