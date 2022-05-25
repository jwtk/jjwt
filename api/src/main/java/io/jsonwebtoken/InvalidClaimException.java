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
 * Exception indicating a parsed claim is invalid in some way.  Subclasses reflect the specific
 * reason the claim is invalid.
 *
 * @see IncorrectClaimException
 * @see MissingClaimException
 * @since 0.6
 */
public class InvalidClaimException extends ClaimJwtException {

    /**
     * The name of the invalid claim.
     */
    private String claimName;

    /**
     * The claim value that could not be validated.
     */
    private Object claimValue;

    /**
     * Creates a new instance with the specified header, claims and explanation message.
     *
     * @param header  the header inspected
     * @param claims  the claims obtained
     * @param message the exception message
     */
    protected InvalidClaimException(Header<?> header, Claims claims, String message) {
        super(header, claims, message);
    }

    /**
     * Creates a new instance with the specified header, claims, explanation message and underlying cause.
     *
     * @param header  the header inspected
     * @param claims  the claims obtained
     * @param message the exception message
     * @param cause   the underlying cause that resulted in this exception being thrown
     */
    protected InvalidClaimException(Header<?> header, Claims claims, String message, Throwable cause) {
        super(header, claims, message, cause);
    }

    /**
     * Returns the name of the invalid claim.
     *
     * @return the name of the invalid claim.
     */
    public String getClaimName() {
        return claimName;
    }

    /**
     * Sets the name of the invalid claim.
     *
     * @param claimName the name of the invalid claim.
     */
    public void setClaimName(String claimName) {
        this.claimName = claimName;
    }

    /**
     * Returns the claim value that could not be validated.
     *
     * @return the claim value that could not be validated.
     */
    public Object getClaimValue() {
        return claimValue;
    }

    /**
     * Sets the claim value that could not be validated.
     *
     * @param claimValue the claim value that could not be validated.
     */
    public void setClaimValue(Object claimValue) {
        this.claimValue = claimValue;
    }
}
