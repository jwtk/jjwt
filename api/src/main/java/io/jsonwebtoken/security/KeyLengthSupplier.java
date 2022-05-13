package io.jsonwebtoken.security;

/**
 * Provides access to the required length in bits <em>(not bytes)</em> of keys usable with the associated algorithm.
 *
 * @since JJWT_RELEASE_VERSION
 */
public interface KeyLengthSupplier {

    /**
     * Returns the required length in bits <em>(not bytes)</em> of keys usable with the associated algorithm.
     *
     * @return the required length in bits <em>(not bytes)</em> of keys usable with the associated algorithm.
     */
    int getKeyBitLength();
}
