package io.jsonwebtoken.security;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface Identifiable {

    /**
     * Returns the unique string identifier of the associated object.
     *
     * @return the unique string identifier of the associated object.
     */
    String getId();
}
