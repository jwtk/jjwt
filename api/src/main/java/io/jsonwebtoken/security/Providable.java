/*
 * Copyright © 2026 jsonwebtoken.io
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

/**
 * Interface implemented by objects that allow configuration of a JCA {@link Provider}.
 *
 * @param <T> the type of object returned after setting the {@code Provider}, usually for method chaining.
 * @see #provider(Provider)
 * @since JJWT_RELEASE_VERSION
 */
@FunctionalInterface
public interface Providable<T> {

    /**
     * Sets the JCA Security {@link Provider} to use during cryptographic operations.  This is an
     * optional property - if not specified, a default JCA Provider will be used if necessary.
     *
     * @param provider the JCA Security Provider instance to use during cryptographic operations.
     * @return the associated object for method chaining.
     */
    T provider(Provider provider);
}
