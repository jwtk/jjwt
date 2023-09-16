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
 * Exception thrown when discovering that a required claim does not equal the required value, indicating the JWT is
 * invalid and may not be used.
 *
 * @since 0.6
 */
public class IncorrectClaimException extends InvalidClaimException {

    /**
     * Creates a new instance with the specified header, claims and explanation message.
     *
     * @param header     the header inspected
     * @param claims     the claims with the incorrect claim value
     * @param claimName  the name of the claim that could not be validated
     * @param claimValue the value of the claim that could not be validated
     * @param message    the exception message
     */
    public IncorrectClaimException(Header header, Claims claims, String claimName, Object claimValue, String message) {
        super(header, claims, claimName, claimValue, message);
    }

    /**
     * Creates a new instance with the specified header, claims, explanation message and underlying cause.
     *
     * @param header     the header inspected
     * @param claims     the claims with the incorrect claim value
     * @param claimName  the name of the claim that could not be validated
     * @param claimValue the value of the claim that could not be validated
     * @param message    the exception message
     * @param cause      the underlying cause that resulted in this exception being thrown
     */
    public IncorrectClaimException(Header header, Claims claims, String claimName, Object claimValue, String message, Throwable cause) {
        super(header, claims, claimName, claimValue, message, cause);
    }
}
