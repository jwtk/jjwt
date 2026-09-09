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
 * @param <B> the type of SecurityBuilder returned for method chaining
 * @see #provider(Provider)
 * @see #random(SecureRandom)
 * @since 0.12.0
 * @deprecated since JJWT_RELEASE_VERSION in favor of extending {@link Providable}, {@link Randomizable} and/or
 * {@link Builder} explicitly when necessary.
 */
@Deprecated
public interface SecurityBuilder<T, B extends SecurityBuilder<T, B>> extends Providable<B>, Randomizable<B>, Builder<T> {
}
