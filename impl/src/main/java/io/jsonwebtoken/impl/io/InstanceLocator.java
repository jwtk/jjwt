package io.jsonwebtoken.impl.io;

/**
 * @since 0.10.0
 */
public interface InstanceLocator<T> {

    T getInstance();
}
