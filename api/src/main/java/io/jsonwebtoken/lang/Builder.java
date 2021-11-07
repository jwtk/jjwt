package io.jsonwebtoken.lang;

/**
 * Type-safe interface that reflects the <a href="https://en.wikipedia.org/wiki/Builder_pattern">Builder pattern</a>.
 *
 * @param <T> The type of object that will be created each time {@link #build()} is invoked.
 * @since JJWT_RELEASE_VERSION
 */
public interface Builder<T> {

    /**
     * Creates and returns a new instance of type {@code T}.
     *
     * @return a new instance of type {@code T}.
     */
    T build();
}
