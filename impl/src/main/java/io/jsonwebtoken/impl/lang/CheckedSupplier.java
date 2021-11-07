package io.jsonwebtoken.impl.lang;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface CheckedSupplier<T> {

    T get() throws Exception;
}
