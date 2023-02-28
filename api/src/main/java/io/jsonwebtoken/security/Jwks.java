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

import io.jsonwebtoken.lang.Classes;

/**
 * Utility methods for creating
 * <a href="https://www.rfc-editor.org/rfc/rfc7517.html">JWKs (JSON Web Keys)</a> with a type-safe builder.
 *
 * <p><b>Standard JWK Thumbprint Algorithm References</b></p>
 * <p>Standard <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA Hash
 * Algorithms</a> commonly used to compute {@link JwkThumbprint JWK Thumbprint}s and ensure valid
 * <a href="https://www.rfc-editor.org/rfc/rfc9278#name-hash-algorithms-identifier">JWK Thumbprint URIs</a>
 * are available via the {@link #HASH} registry constant to allow for easy code-completion in IDEs. For example, when
 * typing:</p>
 * <blockquote><pre>
 * Jwts.{@link #HASH}.// press hotkeys to suggest individual hash algorithms or utility methods</pre></blockquote>
 *
 * @see #builder()
 * @since JJWT_RELEASE_VERSION
 */
public final class Jwks {

    private Jwks() {
    } //prevent instantiation

    private static final String BUILDER_CLASSNAME = "io.jsonwebtoken.impl.security.DefaultProtoJwkBuilder";

    private static final String PARSERBUILDER_CLASSNAME = "io.jsonwebtoken.impl.security.DefaultJwkParserBuilder";

    /**
     * Registry of various (<em>but not all</em>)
     * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA Hash
     * Algorithms</a> commonly used to compute {@link JwkThumbprint JWK Thumbprint}s and ensure valid
     * <a href="https://www.rfc-editor.org/rfc/rfc9278#name-hash-algorithms-identifier">JWK Thumbprint URIs</a>.  For
     * example:
     * <blockquote><pre>
     * Jwks.{@link Jwks#builder}()
     *     // ... etc ...
     *     .{@link JwkBuilder#setIdFromThumbprint(HashAlgorithm) setIdFromThumbprint}(Jwts.HASH.{@link StandardHashAlgorithms#SHA256 SHA256}) // &lt;---
     *     .build()</pre></blockquote>
     * <p>or</p>
     * <blockquote><pre>
     * HashAlgorithm hashAlg = Jwts.HASH.{@link StandardHashAlgorithms#SHA256 SHA256};
     * {@link JwkThumbprint} thumbprint = aJwk.{@link Jwk#thumbprint(HashAlgorithm) thumbprint}(hashAlg);
     * String <a href="https://www.rfc-editor.org/rfc/rfc9278#section-3">rfcMandatoryPrefix</a> = "urn:ietf:params:oauth:jwk-thumbprint:" + hashAlg.getId();
     * assert thumbprint.toURI().toString().startsWith(rfcMandatoryPrefix);
     * </pre></blockquote>
     *
     * @since JJWT_RELEASE_VERSION
     */
    public static final StandardHashAlgorithms HASH = StandardHashAlgorithms.get();

    /**
     * Return a new JWK builder instance, allowing for type-safe JWK builder coercion based on a provided key or key pair.
     *
     * @return a new JWK builder instance, allowing for type-safe JWK builder coercion based on a provided key or key pair.
     */
    public static ProtoJwkBuilder<?, ?> builder() {
        return Classes.newInstance(BUILDER_CLASSNAME);
    }

    /**
     * Return a new thread-safe {@link JwkParserBuilder} to parse JSON strings into {@link Jwk} instances.
     *
     * @return a new thread-safe {@link JwkParserBuilder} to parse JSON strings into {@link Jwk} instances.
     */
    public static JwkParserBuilder parser() {
        return Classes.newInstance(PARSERBUILDER_CLASSNAME);
    }

}
