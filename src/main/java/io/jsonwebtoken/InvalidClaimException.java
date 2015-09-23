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
 *
 * @since 0.6
 */
public class InvalidClaimException extends ClaimJwtException {
    private String claimName;
    private Object claimValue;

    protected InvalidClaimException(Header header, Claims claims, String message) {
        super(header, claims, message);
    }

    protected InvalidClaimException(Header header, Claims claims, String message, Throwable cause) {
        super(header, claims, message, cause);
    }

    public String getClaimName() {
        return claimName;
    }

    public void setClaimName(String claimName) {
        this.claimName = claimName;
    }

    public Object getClaimValue() {
        return claimValue;
    }

    public void setClaimValue(Object claimValue) {
        this.claimValue = claimValue;
    }
}
