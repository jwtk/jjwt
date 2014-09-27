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
 * Exception thrown when receiving a JWT in a particular format/configuration that does not match the format expected
 * by the application.
 *
 * <p>For example, this exception would be thrown if parsing an unsigned plaintext JWT when the application
 * requires a cryptographically signed Claims JWS instead.</p>
 *
 * @since 0.2
 */
public class UnsupportedJwtException extends JwtException {

    public UnsupportedJwtException(String message) {
        super(message);
    }

    public UnsupportedJwtException(String message, Throwable cause) {
        super(message, cause);
    }
}
