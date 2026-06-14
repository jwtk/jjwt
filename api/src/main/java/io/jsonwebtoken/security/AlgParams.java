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
import java.security.SecureRandom;

/**
 * An algorithm parameters instance aggregates values submitted to a cryptographic algorithm during a cryptographic
 * operation. It and any of its subtypes implemented as a single object effectively reflect the
 * <a href="https://java-design-patterns.com/patterns/parameter-object/">Parameter Object</a> design pattern.  This
 * provides for a much cleaner request/result algorithm API instead of polluting the API with an excessive number of
 * overloaded methods that would exist otherwise.
 *
 * <p>The {@code AlgParams} interface specifically allows for JCA {@link Provider} and {@link SecureRandom} instances
 * to be specified for each algorithm operation or execution, which is more flexible than the alternative
 * of specifying a {@code Provider} or {@code SecureRandom} for all operations. {@code AlgParams} subtypes
 * provide additional parameters as necessary depending on the type of cryptographic operation performed.</p>
 *
 * @param <P> the subtype returned for method chaining.
 * @see #provider(Provider)
 * @see #random(SecureRandom)
 * @since JJWT_RELEASE_VERSION
 */
public interface AlgParams<P extends AlgParams<P>> {

    /**
     * Sets the JCA provider that should be used for the cryptographic operation or
     * {@code null} if the JCA subsystem preferred provider should be used.
     *
     * @param provider the JCA provider that should be used for the cryptographic operation or
     *                 {@code null} if the JCA subsystem preferred provider should be used.
     * @return the instance for method chaining.
     */
    P provider(Provider provider);

    /**
     * Sets the {@code SecureRandom} that should be used for the cryptographic operation if necessary, or {@code null}
     * if a default {@link SecureRandom} should be used.
     *
     * @param random the {@code SecureRandom} that should be used for the cryptographic operation if necessary, or
     *               {@code null} if a default {@link SecureRandom} should be used.
     * @return the instance for method chaining.
     */
    P random(SecureRandom random);

}
