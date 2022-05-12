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
package io.jsonwebtoken.security;

/**
 * A {@code KeyException} thrown when encountering a key that is not suitable for the required functionality, or
 * when attempting to use a Key in an incorrect or prohibited manner.
 *
 * @since 0.10.0
 */
public class InvalidKeyException extends KeyException {

    public InvalidKeyException(String message) {
        super(message);
    }

    /**
     * Creates a new {@code InvalidKeyException} with the specified message and cause.
     *
     * @param msg   exception message
     * @param cause triggering cause for the InvalidKeyException
     * @since JJWT_RELEASE_VERSION
     */
    public InvalidKeyException(String msg, Exception cause) {
        super(msg, cause);
    }
}
