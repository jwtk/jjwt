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
package io.jsonwebtoken;

/**
 * An encrypted JWT, called a &quot;JWE&quot;, per the
 * <a href="https://datatracker.ietf.org/doc/html/rfc7516">JWE (RFC 7516) Specification</a>.
 *
 * @param <B> payload type, either {@link Claims} or {@code byte[]} content.
 * @since JJWT_RELEASE_VERSION
 */
public interface Jwe<B> extends Jwt<JweHeader, B> {

    /**
     * Returns the Initialization Vector used during JWE encryption and decryption.
     *
     * @return the Initialization Vector used during JWE encryption and decryption.
     */
    byte[] getInitializationVector();

    /**
     * Returns the Additional Authenticated Data authentication Tag used for JWE header
     * authenticity and integrity verification.
     *
     * @return the Additional Authenticated Data authentication Tag used for JWE header
     * authenticity and integrity verification.
     */
    byte[] getAadTag();
}
