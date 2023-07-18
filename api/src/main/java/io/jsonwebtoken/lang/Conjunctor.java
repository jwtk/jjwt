package io.jsonwebtoken.lang;

/**
 * A {@code Conjunctor} supplies access to an associated object, typically useful for method chaining.
 *
 * @param <T> the type of asssociated object
 * @since JJWT_RELEASE_VERSION
 */
public interface Conjunctor<T> {

    /**
     * Returns the associated object, typically useful for method chaining.
     *
     * @return the associated object.
     */
    T and();
}
