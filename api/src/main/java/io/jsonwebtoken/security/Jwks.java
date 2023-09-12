/*
 * Copyright (C) 2021 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.jsonwebtoken.security;

import io.jsonwebtoken.Identifiable;
import io.jsonwebtoken.io.Parser;
import io.jsonwebtoken.lang.Classes;
import io.jsonwebtoken.lang.Registry;

/**
 * Utility methods for creating
 * <a href="https://www.rfc-editor.org/rfc/rfc7517.html">JWKs (JSON Web Keys)</a> with a type-safe builder.
 *
 * <p><b>Standard JWK Thumbprint Algorithm References</b></p>
 * <p>Standard <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA Hash
 * Algorithms</a> commonly used to compute {@link JwkThumbprint JWK Thumbprint}s and ensure valid
 * <a href="https://www.rfc-editor.org/rfc/rfc9278#name-hash-algorithms-identifier">JWK Thumbprint URIs</a>
 * are available via the {@link Jwks.HASH} registry constants to allow for easy code-completion in IDEs. For example, when
 * typing:</p>
 * <blockquote><pre>
 * Jwks.{@link Jwks.HASH HASH}.// press hotkeys to suggest individual hash algorithms or utility methods</pre></blockquote>
 *
 * @see #builder()
 * @since JJWT_RELEASE_VERSION
 */
public final class Jwks {

    private Jwks() {
    } //prevent instantiation

    private static final String BUILDER_FQCN = "io.jsonwebtoken.impl.security.DefaultDynamicJwkBuilder";
    private static final String PARSER_BUILDER_FQCN = "io.jsonwebtoken.impl.security.DefaultJwkParserBuilder";
    private static final String SET_BUILDER_FQCN = "io.jsonwebtoken.impl.security.DefaultJwkSetBuilder";
    private static final String SET_PARSER_BUILDER_FQCN = "io.jsonwebtoken.impl.security.DefaultJwkSetParserBuilder";

    /**
     * Return a new JWK builder instance, allowing for type-safe JWK builder coercion based on a specified key or key pair.
     *
     * @return a new JWK builder instance, allowing for type-safe JWK builder coercion based on a specified key or key pair.
     */
    public static DynamicJwkBuilder<?, ?> builder() {
        return Classes.newInstance(BUILDER_FQCN);
    }

    /**
     * Returns a new builder used to create {@link Parser}s that parse JSON into {@link Jwk} instances. For example:
     * <blockquote><pre>
     * Jwk&lt;?&gt; jwk = Jwks.parser()
     *         //.provider(aJcaProvider)     // optional
     *         //.deserializer(deserializer) // optional
     *         //.operationPolicy(policy)    // optional
     *         .build()
     *         .parse(jwkString);</pre></blockquote>
     *
     * @return a new builder used to create {@link Parser}s that parse JSON into {@link Jwk} instances.
     */
    public static JwkParserBuilder parser() {
        return Classes.newInstance(PARSER_BUILDER_FQCN);
    }

    /**
     * Return a new builder used to create {@link JwkSet}s.  For example:
     * <blockquote><pre>
     * JwkSet jwkSet = Jwks.set()
     *     //.provider(aJcaProvider)     // optional
     *     //.operationPolicy(policy)    // optional
     *     .add(aJwk)                    // appends a key
     *     .add(aCollection)             // appends multiple keys
     *     //.keys(allJwks)              // sets/replaces all keys
     *     .build()
     * </pre></blockquote>
     *
     * @return a new builder used to create {@link JwkSet}s
     */
    public static JwkSetBuilder set() {
        return Classes.newInstance(SET_BUILDER_FQCN);
    }

    /**
     * Returns a new builder used to create {@link Parser}s that parse JSON into {@link JwkSet} instances. For example:
     * <blockquote><pre>
     * JwkSet jwkSet = Jwks.setParser()
     *         //.provider(aJcaProvider)     // optional
     *         //.deserializer(deserializer) // optional
     *         //.operationPolicy(policy)    // optional
     *         .build()
     *         .parse(jwkSetString);</pre></blockquote>
     *
     * @return a new builder used to create {@link Parser}s that parse JSON into {@link JwkSet} instances.
     */
    public static JwkSetParserBuilder setParser() {
        return Classes.newInstance(SET_PARSER_BUILDER_FQCN);
    }

    /**
     * Constants for all standard JWK
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.1.1">crv (Curve)</a> parameter values
     * defined in the <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-7.6">JSON Web Key Elliptic
     * Curve Registry</a> (including its
     * <a href="https://www.rfc-editor.org/rfc/rfc8037#section-5">Edwards Elliptic Curve additions</a>).
     * Each standard algorithm is available as a ({@code public static final}) constant for direct type-safe
     * reference in application code. For example:
     * <blockquote><pre>
     * Jwks.CRV.P256.keyPair().build();</pre></blockquote>
     * <p>They are also available together as a {@link Registry} instance via the {@link #get()} method.</p>
     *
     * @see #get()
     * @since JJWT_RELEASE_VERSION
     */
    public static final class CRV {

        private static final String IMPL_CLASSNAME = "io.jsonwebtoken.impl.security.StandardCurves";
        private static final Registry<String, Curve> REGISTRY = Classes.newInstance(IMPL_CLASSNAME);

        /**
         * Returns a registry of all standard Elliptic Curves in the {@code JSON Web Key Elliptic Curve Registry}
         * defined by <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-7.6">RFC 7518, Section 7.6</a>
         * (for Weierstrass Elliptic Curves) and
         * <a href="https://www.rfc-editor.org/rfc/rfc8037#section-5">RFC 8037, Section 5</a> (for Edwards Elliptic Curves).
         *
         * @return a registry of all standard Elliptic Curves in the {@code JSON Web Key Elliptic Curve Registry}.
         */
        public static Registry<String, Curve> get() {
            return REGISTRY;
        }

        /**
         * {@code P-256} Elliptic Curve defined by
         * <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.1">RFC 7518, Section 6.2.1.1</a>
         * using the native Java JCA {@code secp256r1} algorithm.
         *
         * @see <a href="https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html">Java Security Standard Algorithm Names</a>
         */
        public static final Curve P256 = get().forKey("P-256");

        /**
         * {@code P-384} Elliptic Curve defined by
         * <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.1">RFC 7518, Section 6.2.1.1</a>
         * using the native Java JCA {@code secp384r1} algorithm.
         *
         * @see <a href="https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html">Java Security Standard Algorithm Names</a>
         */
        public static final Curve P384 = get().forKey("P-384");

        /**
         * {@code P-521} Elliptic Curve defined by
         * <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.1">RFC 7518, Section 6.2.1.1</a>
         * using the native Java JCA {@code secp521r1} algorithm.
         *
         * @see <a href="https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html">Java Security Standard Algorithm Names</a>
         */
        public static final Curve P521 = get().forKey("P-521");

        /**
         * {@code Ed25519} Elliptic Curve defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc8037#section-3.1">RFC 8037, Section 3.1</a>
         * using the native Java JCA {@code Ed25519}<b><sup>1</sup></b> algorithm.
         *
         * <p><b><sup>1</sup></b> Requires Java 15 or a compatible JCA Provider (like BouncyCastle) in the runtime
         * classpath. If on Java 14 or earlier, BouncyCastle will be used automatically if found in the runtime
         * classpath.</p>
         *
         * @see <a href="https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html">Java Security Standard Algorithm Names</a>
         */
        public static final Curve Ed25519 = get().forKey("Ed25519");

        /**
         * {@code Ed448} Elliptic Curve defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc8037#section-3.1">RFC 8037, Section 3.1</a>
         * using the native Java JCA {@code Ed448}<b><sup>1</sup></b> algorithm.
         *
         * <p><b><sup>1</sup></b> Requires Java 15 or a compatible JCA Provider (like BouncyCastle) in the runtime
         * classpath. If on Java 14 or earlier, BouncyCastle will be used automatically if found in the runtime
         * classpath.</p>
         *
         * @see <a href="https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html">Java Security Standard Algorithm Names</a>
         */
        public static final Curve Ed448 = get().forKey("Ed448");

        /**
         * {@code X25519} Elliptic Curve defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc8037#section-3.2">RFC 8037, Section 3.2</a>
         * using the native Java JCA {@code X25519}<b><sup>1</sup></b> algorithm.
         *
         * <p><b><sup>1</sup></b> Requires Java 11 or a compatible JCA Provider (like BouncyCastle) in the runtime
         * classpath. If on Java 10 or earlier, BouncyCastle will be used automatically if found in the runtime
         * classpath.</p>
         *
         * @see <a href="https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html">Java Security Standard Algorithm Names</a>
         */
        public static final Curve X25519 = get().forKey("X25519");

        /**
         * {@code X448} Elliptic Curve defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc8037#section-3.2">RFC 8037, Section 3.2</a>
         * using the native Java JCA {@code X448}<b><sup>1</sup></b> algorithm.
         *
         * <p><b><sup>1</sup></b> Requires Java 11 or a compatible JCA Provider (like BouncyCastle) in the runtime
         * classpath. If on Java 10 or earlier, BouncyCastle will be used automatically if found in the runtime
         * classpath.</p>
         *
         * @see <a href="https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html">Java Security Standard Algorithm Names</a>
         */
        public static final Curve X448 = get().forKey("X448");

        //prevent instantiation
        private CRV() {
        }
    }

    /**
     * Various (<em>but not all</em>)
     * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA Hash
     * Algorithms</a> commonly used to compute {@link JwkThumbprint JWK Thumbprint}s and ensure valid
     * <a href="https://www.rfc-editor.org/rfc/rfc9278#name-hash-algorithms-identifier">JWK Thumbprint URIs</a>.
     * Each algorithm is made available as a ({@code public static final}) constant for direct type-safe
     * reference in application code. For example:
     * <blockquote><pre>
     * Jwks.{@link Jwks#builder}()
     *     // ... etc ...
     *     .{@link JwkBuilder#idFromThumbprint(HashAlgorithm) idFromThumbprint}(Jwts.HASH.{@link Jwks.HASH#SHA256 SHA256}) // &lt;---
     *     .build()</pre></blockquote>
     * <p>or</p>
     * <blockquote><pre>
     * HashAlgorithm hashAlg = Jwks.HASH.{@link Jwks.HASH#SHA256 SHA256};
     * {@link JwkThumbprint} thumbprint = aJwk.{@link Jwk#thumbprint(HashAlgorithm) thumbprint}(hashAlg);
     * String <a href="https://www.rfc-editor.org/rfc/rfc9278#section-3">rfcMandatoryPrefix</a> = "urn:ietf:params:oauth:jwk-thumbprint:" + hashAlg.getId();
     * assert thumbprint.toURI().toString().startsWith(rfcMandatoryPrefix);
     * </pre></blockquote>
     * <p>They are also available together as a {@link Registry} instance via the {@link #get()} method.</p>
     *
     * @see #get()
     * @since JJWT_RELEASE_VERSION
     */
    public static final class HASH {

        private static final String IMPL_CLASSNAME = "io.jsonwebtoken.impl.security.StandardHashAlgorithms";
        private static final Registry<String, HashAlgorithm> REGISTRY = Classes.newInstance(IMPL_CLASSNAME);

        /**
         * Returns a registry of various (<em>but not all</em>)
         * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA Hash
         * Algorithms</a> commonly used to compute {@link JwkThumbprint JWK Thumbprint}s and ensure valid
         * <a href="https://www.rfc-editor.org/rfc/rfc9278#name-hash-algorithms-identifier">JWK Thumbprint URIs</a>.
         *
         * @return a registry of various (<em>but not all</em>)
         * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA Hash
         * Algorithms</a> commonly used to compute {@link JwkThumbprint JWK Thumbprint}s and ensure valid
         * <a href="https://www.rfc-editor.org/rfc/rfc9278#name-hash-algorithms-identifier">JWK Thumbprint URIs</a>.
         */
        public static Registry<String, HashAlgorithm> get() {
            return REGISTRY;
        }

        /**
         * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA
         * hash algorithm</a> with an {@link Identifiable#getId() id} (aka IANA &quot;{@code Hash Name String}&quot;)
         * value of {@code sha-256}. It is a {@code HashAlgorithm} alias for the native
         * Java JCA {@code SHA-256} {@code MessageDigest} algorithm.
         */
        public static final HashAlgorithm SHA256 = get().forKey("sha-256");

        /**
         * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA
         * hash algorithm</a> with an {@link Identifiable#getId() id} (aka IANA &quot;{@code Hash Name String}&quot;)
         * value of {@code sha-384}. It is a {@code HashAlgorithm} alias for the native
         * Java JCA {@code SHA-384} {@code MessageDigest} algorithm.
         */
        public static final HashAlgorithm SHA384 = get().forKey("sha-384");

        /**
         * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA
         * hash algorithm</a> with an {@link Identifiable#getId() id} (aka IANA &quot;{@code Hash Name String}&quot;)
         * value of {@code sha-512}. It is a {@code HashAlgorithm} alias for the native
         * Java JCA {@code SHA-512} {@code MessageDigest} algorithm.
         */
        public static final HashAlgorithm SHA512 = get().forKey("sha-512");

        /**
         * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA
         * hash algorithm</a> with an {@link Identifiable#getId() id} (aka IANA &quot;{@code Hash Name String}&quot;)
         * value of {@code sha3-256}. It is a {@code HashAlgorithm} alias for the native
         * Java JCA {@code SHA3-256} {@code MessageDigest} algorithm.
         * <p><b>This algorithm requires at least JDK 9 or a compatible JCA Provider (like BouncyCastle) in the runtime
         * classpath.</b></p>
         */
        public static final HashAlgorithm SHA3_256 = get().forKey("sha3-256");

        /**
         * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA
         * hash algorithm</a> with an {@link Identifiable#getId() id} (aka IANA &quot;{@code Hash Name String}&quot;)
         * value of {@code sha3-384}. It is a {@code HashAlgorithm} alias for the native
         * Java JCA {@code SHA3-384} {@code MessageDigest} algorithm.
         * <p><b>This algorithm requires at least JDK 9 or a compatible JCA Provider (like BouncyCastle) in the runtime
         * classpath.</b></p>
         */
        public static final HashAlgorithm SHA3_384 = get().forKey("sha3-384");

        /**
         * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA
         * hash algorithm</a> with an {@link Identifiable#getId() id} (aka IANA &quot;{@code Hash Name String}&quot;)
         * value of {@code sha3-512}. It is a {@code HashAlgorithm} alias for the native
         * Java JCA {@code SHA3-512} {@code MessageDigest} algorithm.
         * <p><b>This algorithm requires at least JDK 9 or a compatible JCA Provider (like BouncyCastle) in the runtime
         * classpath.</b></p>
         */
        public static final HashAlgorithm SHA3_512 = get().forKey("sha3-512");

        //prevent instantiation
        private HASH() {
        }
    }

    /**
     * Constants for all standard JWK
     * <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-4.3">key_ops (Key Operations)</a> parameter values
     * defined in the <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-8.3">JSON Web Key Operations
     * Registry</a>. Each standard key operation is available as a ({@code public static final}) constant for
     * direct type-safe reference in application code. For example:
     * <blockquote><pre>
     * Jwks.builder()
     *     .operations(Jwks.OP.SIGN)
     *     // ... etc ...
     *     .build();</pre></blockquote>
     * <p>They are also available together as a {@link Registry} instance via the {@link #get()} method.</p>
     *
     * @see #get()
     * @since JJWT_RELEASE_VERSION
     */
    public static final class OP {

        private static final String IMPL_CLASSNAME = "io.jsonwebtoken.impl.security.StandardKeyOperations";
        private static final Registry<String, KeyOperation> REGISTRY = Classes.newInstance(IMPL_CLASSNAME);

        private static final String BUILDER_CLASSNAME = "io.jsonwebtoken.impl.security.DefaultKeyOperationBuilder";


        private static final String POLICY_BUILDER_CLASSNAME =
                "io.jsonwebtoken.impl.security.DefaultKeyOperationPolicyBuilder";

        /**
         * Creates a new {@link KeyOperationBuilder} for creating custom {@link KeyOperation} instances.
         *
         * @return a new {@link KeyOperationBuilder} for creating custom {@link KeyOperation} instances.
         */
        public static KeyOperationBuilder builder() {
            return Classes.newInstance(BUILDER_CLASSNAME);
        }

        /**
         * Creates a new {@link KeyOperationPolicyBuilder} for creating custom {@link KeyOperationPolicy} instances.
         *
         * @return a new {@link KeyOperationPolicyBuilder} for creating custom {@link KeyOperationPolicy} instances.
         */
        public static KeyOperationPolicyBuilder policy() {
            return Classes.newInstance(POLICY_BUILDER_CLASSNAME);
        }

        /**
         * Returns a registry of all standard Key Operations in the {@code JSON Web Key Operations Registry}
         * defined by <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-8.3">RFC 7517, Section 8.3</a>.
         *
         * @return a registry of all standard Key Operations in the {@code JSON Web Key Operations Registry}.
         */
        public static Registry<String, KeyOperation> get() {
            return REGISTRY;
        }

        /**
         * {@code sign} operation indicating a key is intended to be used to compute digital signatures or
         * MACs. It's related operation is {@link #VERIFY}.
         *
         * @see #VERIFY
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-8.3.2">Key Operation Registry Contents</a>
         */
        public static final KeyOperation SIGN = get().forKey("sign");

        /**
         * {@code verify} operation indicating a key is intended to be used to verify digital signatures or
         * MACs. It's related operation is {@link #SIGN}.
         *
         * @see #SIGN
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-8.3.2">Key Operation Registry Contents</a>
         */
        public static final KeyOperation VERIFY = get().forKey("verify");

        /**
         * {@code encrypt} operation indicating a key is intended to be used to encrypt content. It's
         * related operation is {@link #DECRYPT}.
         *
         * @see #DECRYPT
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-8.3.2">Key Operation Registry Contents</a>
         */
        public static final KeyOperation ENCRYPT = get().forKey("encrypt");

        /**
         * {@code decrypt} operation indicating a key is intended to be used to decrypt content. It's
         * related operation is {@link #ENCRYPT}.
         *
         * @see #ENCRYPT
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-8.3.2">Key Operation Registry Contents</a>
         */
        public static final KeyOperation DECRYPT = get().forKey("decrypt");

        /**
         * {@code wrapKey} operation indicating a key is intended to be used to encrypt another key. It's
         * related operation is {@link #UNWRAP_KEY}.
         *
         * @see #UNWRAP_KEY
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-8.3.2">Key Operation Registry Contents</a>
         */
        public static final KeyOperation WRAP_KEY = get().forKey("wrapKey");

        /**
         * {@code unwrapKey} operation indicating a key is intended to be used to decrypt another key and validate
         * decryption, if applicable. It's related operation is
         * {@link #WRAP_KEY}.
         *
         * @see #WRAP_KEY
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-8.3.2">Key Operation Registry Contents</a>
         */
        public static final KeyOperation UNWRAP_KEY = get().forKey("unwrapKey");

        /**
         * {@code deriveKey} operation indicating a key is intended to be used to derive another key. It does not have
         * a related operation.
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-8.3.2">Key Operation Registry Contents</a>
         */
        public static final KeyOperation DERIVE_KEY = get().forKey("deriveKey");

        /**
         * {@code deriveBits} operation indicating a key is intended to be used to derive bits that are not to be
         * used as key. It does not have a related operation.
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-8.3.2">Key Operation Registry Contents</a>
         */
        public static final KeyOperation DERIVE_BITS = get().forKey("deriveBits");

        //prevent instantiation
        private OP() {
        }
    }
}
