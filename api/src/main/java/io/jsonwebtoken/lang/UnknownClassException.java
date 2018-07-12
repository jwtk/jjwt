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
package io.jsonwebtoken.lang;

/**
 * A <code>RuntimeException</code> equivalent of the JDK's
 * <code>ClassNotFoundException</code>, to maintain a RuntimeException paradigm.
 *
 * @since 0.1
 */
public class UnknownClassException extends RuntimeException {

    /*
    /**
     * Creates a new UnknownClassException.
     *
    public UnknownClassException() {
        super();
    }*/

    /**
     * Constructs a new UnknownClassException.
     *
     * @param message the reason for the exception
     */
    public UnknownClassException(String message) {
        super(message);
    }

    /*
     * Constructs a new UnknownClassException.
     *
     * @param cause the underlying Throwable that caused this exception to be thrown.
     *
    public UnknownClassException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new UnknownClassException.
     *
     * @param message the reason for the exception
     * @param cause   the underlying Throwable that caused this exception to be thrown.
     *
    public UnknownClassException(String message, Throwable cause) {
        super(message, cause);
    }
    */

}