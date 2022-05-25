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
 * Exception thrown when encountering a key that is not strong enough (of sufficient length) to be used with
 * a particular algorithm or in a particular security context.
 *
 * @since 0.10.0
 */
public class WeakKeyException extends InvalidKeyException {

    /**
     * Creates a new instance with the specified explanation message.
     *
     * @param message the message explaining why the exception is thrown.
     */
    public WeakKeyException(String message) {
        super(message);
    }
}
