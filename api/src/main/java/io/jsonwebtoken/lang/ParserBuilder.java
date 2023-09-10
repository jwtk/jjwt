package io.jsonwebtoken.lang;

import io.jsonwebtoken.io.Deserializer;
import io.jsonwebtoken.security.JwkParserBuilder;

import java.security.Provider;
import java.util.Map;

public interface ParserBuilder<T extends Parser, P extends ParserBuilder<T, P>> extends Builder<T> {

    /**
     * Sets the JCA Provider to use during cryptographic key factory operations, or {@code null} if the
     * JCA subsystem preferred provider should be used.
     *
     * @param provider the JCA Provider to use during cryptographic key factory operations, or {@code null}
     *                 if the JCA subsystem preferred provider should be used.
     * @return the builder for method chaining.
     */
    JwkParserBuilder provider(Provider provider);

    /**
     * Uses the specified deserializer to convert JSON Strings (UTF-8 byte arrays) into Java Map objects.  The
     * resulting Maps are then used to construct respective JWT objects (JWTs, JWKs, etc).
     *
     * <p>If this method is not called, JJWT will use whatever deserializer it can find at runtime, checking for the
     * presence of well-known implementations such Jackson, Gson, and org.json.  If one of these is not found
     * in the runtime classpath, an exception will be thrown when the resulting {@link Parser}'s
     * {@link Parser#parse parse} method is called.
     *
     * @param deserializer the deserializer to use when converting JSON Strings (UTF-8 byte arrays) into Map objects.
     * @return the builder for method chaining.
     */
    JwkParserBuilder deserializer(Deserializer<Map<String, ?>> deserializer);
}
