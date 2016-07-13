package io.jsonwebtoken;

import java.util.Date;

/**
 * A clock represents a time source that can be used when creating and verifying JWTs.
 *
 * @since 0.7.0
 */
public interface Clock {

    /**
     * Returns the clock's current timestamp at the instant the method is invoked.
     *
     * @return the clock's current timestamp at the instant the method is invoked.
     */
    Date now();
}
