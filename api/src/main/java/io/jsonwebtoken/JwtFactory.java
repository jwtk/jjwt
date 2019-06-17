package io.jsonwebtoken;

import java.util.Map;

/**
 * Factory for creating instances of JWT interfaces. Backs the {@link io.jsonwebtoken.Jwts} factory class.
 * Implementations of jjwt-api should provide their own implementation and make it available via a provider
 * configuration file in META-INF/services.
 *
 * @since 0.1
 */
public interface JwtFactory {

    /**
     * Creates a new {@link Header} instance suitable for <em>plaintext</em> (not digitally signed) JWTs.  As this
     * is a less common use of JWTs, consider using the {@link #jwsHeader()} factory method instead if you will later
     * digitally sign the JWT.
     *
     * @return a new {@link Header} instance suitable for <em>plaintext</em> (not digitally signed) JWTs.
     */
    Header header();

    /**
     * Creates a new {@link Header} instance suitable for <em>plaintext</em> (not digitally signed) JWTs, populated
     * with the specified name/value pairs. As this is a less common use of JWTs, consider using the
     * {@link #jwsHeader(java.util.Map)} factory method instead if you will later digitally sign the JWT.
     *
     * @return a new {@link Header} instance suitable for <em>plaintext</em> (not digitally signed) JWTs.
     */
    Header header(Map<String, Object> header);

    /**
     * Returns a new {@link JwsHeader} instance suitable for digitally signed JWTs (aka 'JWS's).
     *
     * @return a new {@link JwsHeader} instance suitable for digitally signed JWTs (aka 'JWS's).
     * @see JwtBuilder#setHeader(Header)
     */
    JwsHeader jwsHeader();

    /**
     * Returns a new {@link JwsHeader} instance suitable for digitally signed JWTs (aka 'JWS's), populated with the
     * specified name/value pairs.
     *
     * @return a new {@link JwsHeader} instance suitable for digitally signed JWTs (aka 'JWS's), populated with the
     * specified name/value pairs.
     * @see JwtBuilder#setHeader(Header)
     */
    JwsHeader jwsHeader(Map<String, Object> header);

    /**
     * Returns a new {@link Claims} instance to be used as a JWT body.
     *
     * @return a new {@link Claims} instance to be used as a JWT body.
     */
    Claims claims();

    /**
     * Returns a new {@link Claims} instance populated with the specified name/value pairs.
     *
     * @param claims the name/value pairs to populate the new Claims instance.
     * @return a new {@link Claims} instance populated with the specified name/value pairs.
     */
    Claims claims(Map<String, Object> claims);

    /**
     * Returns a new {@link JwtParser} instance that can be configured and then used to parse JWT strings.
     *
     * @return a new {@link JwtParser} instance that can be configured and then used to parse JWT strings.
     */
    JwtParser parser();

    /**
     * Returns a new {@link JwtBuilder} instance that can be configured and then used to create JWT compact serialized
     * strings.
     *
     * @return a new {@link JwtBuilder} instance that can be configured and then used to create JWT compact serialized
     * strings.
     */
    JwtBuilder builder();
}
