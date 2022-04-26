package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.lang.Classes;
import io.jsonwebtoken.lang.UnknownClassException;

/**
 * A backward compatibility {@link Services} utility to help migrate away from {@link Classes#newInstance(String)}.
 * TODO: remove before v1.0
 * @deprecated use {@link Services} directly
 */
@Deprecated
public final class LegacyServices {

    /**
     * Wraps {@code Services.loadFirst} and throws a {@link UnknownClassException} instead of a
     * {@link UnavailableImplementationException} to retain the previous behavior. This method should be used when
     * to retain the previous behavior of methods that throw an unchecked UnknownClassException.
     * @param <T> the type of object to return
     * @param spi the class for which to find the first instance
     * @return the first instance of type {@code T} found from a call to {@link Services#loadFirst(Class)}
     */
    public static <T> T loadFirst(Class<T> spi) {
        try {
            return Services.loadFirst(spi);
        } catch (UnavailableImplementationException e) {
            throw new UnknownClassException(e.getMessage(), e);
        }
    }
}
