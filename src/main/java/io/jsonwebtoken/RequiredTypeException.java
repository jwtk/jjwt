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
 * Exception thrown when {@link Claims#get(String, Class)} is called and the value does not match the type of the
 * {@code Class} argument.
 *
 * @since 0.6
 */
public class RequiredTypeException extends JwtException {
    public RequiredTypeException(String message) {
        super(message);
    }

    public RequiredTypeException(String message, Throwable cause) {
        super(message, cause);
    }
}
