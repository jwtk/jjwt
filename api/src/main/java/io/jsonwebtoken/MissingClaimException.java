/*
 * Copyright (C) 2015 jsonwebtoken.io
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
 * Exception thrown when discovering that a required claim is not present, indicating the JWT is
 * invalid and may not be used.
 *
 * @since 0.6
 */
public class MissingClaimException extends InvalidClaimException {

    /**
     * Creates a new instance with the specified explanation message.
     *
     * @param header     the header associated with the claims that did not contain the required claim
     * @param claims     the claims that did not contain the required claim
     * @param claimName  the name of the claim that could not be validated
     * @param claimValue the value of the claim that could not be validated
     * @param message    the message explaining why the exception is thrown.
     */
    public MissingClaimException(Header header, Claims claims, String claimName, Object claimValue, String message) {
        super(header, claims, claimName, claimValue, message);
    }


    /**
     * Creates a new instance with the specified explanation message and underlying cause.
     *
     * @param header     the header associated with the claims that did not contain the required claim
     * @param claims     the claims that did not contain the required claim
     * @param claimName  the name of the claim that could not be validated
     * @param claimValue the value of the claim that could not be validated
     * @param message    the message explaining why the exception is thrown.
     * @param cause      the underlying cause that resulted in this exception being thrown.
     * @deprecated since JJWT_RELEASE_VERSION since it is not used in JJWT's codebase
     */
    @Deprecated
    public MissingClaimException(Header header, Claims claims, String claimName, Object claimValue, String message, Throwable cause) {
        super(header, claims, claimName, claimValue, message, cause);
    }
}
