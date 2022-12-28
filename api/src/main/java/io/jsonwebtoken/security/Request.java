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
 * A {@code Request} aggregates various parameters that may be used by a particular cryptographic algorithm. It and
 * any of its subtypes implemented as a single object submitted to an algorithm effectively reflect the
 * <a href="https://java-design-patterns.com/patterns/parameter-object/">Parameter Object</a> design pattern.  This
 * provides for a much cleaner request/result algorithm API instead of polluting the API with an excessive number of
 * overloaded methods that would exist otherwise.
 *
 * <p>The {@code Request} interface specifically allows for JCA {@link Provider} and {@link SecureRandom} instances
 * to be used during request execution, which allows more flexibility than forcing a single {@code Provider} or
 * {@code SecureRandom} for all executions. {@code Request} subtypes provide additional parameters as necessary
 * depending on the type of cryptographic algorithm invoked.</p>
 *
 * @param <T> the type of payload in the request.
 * @see #getProvider()
 * @see #getSecureRandom()
 * @since JJWT_RELEASE_VERSION
 */
public interface Request<T> extends Message<T> {

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
