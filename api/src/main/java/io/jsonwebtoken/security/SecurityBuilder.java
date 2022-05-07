package io.jsonwebtoken.security;

import io.jsonwebtoken.lang.Builder;

import java.security.Provider;
import java.security.SecureRandom;

/**
 * A Security-specific {@link Builder} that allows configuration of common JCA API parameters, such as a
 * {@link java.security.Provider} or {@link java.security.SecureRandom}.
 *
 * @param <T> The type of object that will be created each time {@link #build()} is invoked.
 * @see #setProvider(Provider)
 * @see #setRandom(SecureRandom)
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
    B setProvider(Provider provider);

    /**
     * Sets the {@link SecureRandom} to use if necessary when calling {@link #build()}.  This is an optional property
     * - if not specified and one is required, a default {@code SecureRandom} will be used.
     *
     * @param random the {@link SecureRandom} instance to use if necessary when building the new instance.
     * @return the builder for method chaining.
     */
    B setRandom(SecureRandom random);
}
