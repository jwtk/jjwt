/*
 * Copyright (C) 2014 jsonwebtoken.io
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
 * Exception indicating that a JWT was accepted after it expired and must be rejected.
 *
 * @since 0.3
 */
public class ExpiredJwtException extends ClaimJwtException {

    public ExpiredJwtException(Header header, Claims claims, String message) {
        super(header, claims, message);
    }

    /**
     * @param header jwt header
     * @param claims jwt claims (body)
     * @param message exception message
     * @param cause cause
     * @since 0.5
     */
    public ExpiredJwtException(Header header, Claims claims, String message, Throwable cause) {
        super(header, claims, message, cause);
    }
}
