package io.jsonwebtoken.io;

import io.jsonwebtoken.lang.Builder;

import java.security.Provider;
import java.util.Map;

/**
 * A {@code ParserBuilder} configures and creates new {@link Parser} instances.
 *
 * @param <T> The resulting parser's {@link Parser#parse parse} output type
 * @param <B> builder type used for method chaining
 * @since JJWT_RELEASE_VERSION
 */
public interface ParserBuilder<T, B extends ParserBuilder<T, B>> extends Builder<Parser<T>> {

    /**
     * Sets the JCA Provider to use during cryptographic operations, or {@code null} if the
     * JCA subsystem preferred provider should be used.
     *
     * @param provider the JCA Provider to use during cryptographic key factory operations, or {@code null}
     *                 if the JCA subsystem preferred provider should be used.
     * @return the builder for method chaining.
     */
    B provider(Provider provider);

    /**
     * Uses the specified deserializer to convert JSON Strings (UTF-8 byte arrays) into Java Map objects.  The
     * resulting Maps are then used to construct respective JWT objects (JWTs, JWKs, etc).
     *
     * <p>If this method is not called, JJWT will use whatever deserializer it can find at runtime, checking for the
     * presence of well-known implementations such as Jackson, Gson, and org.json.  If one of these is not found
     * in the runtime classpath, an exception will be thrown when the {@link #build()} method is called.
     *
     * @param deserializer the deserializer to use when converting JSON Strings (UTF-8 byte arrays) into Map objects.
     * @return the builder for method chaining.
     */
    B deserializer(Deserializer<Map<String, ?>> deserializer);
}
