/*
 * Copyright (C) 2019 jsonwebtoken.io
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
package io.jsonwebtoken.impl.lang;

/**
 * Exception indicating that no implementation of an jjwt-api SPI was found on the classpath.
 * @since 0.11.0
 */
public final class UnavailableImplementationException extends RuntimeException {

    private static final String DEFAULT_NOT_FOUND_MESSAGE = "Unable to find an implementation for %s using java.util.ServiceLoader. Ensure you include a backing implementation .jar in the classpath, for example jjwt-impl.jar, or your own .jar for custom implementations.";

    UnavailableImplementationException(final Class klass) {
        super(String.format(DEFAULT_NOT_FOUND_MESSAGE, klass));
    }
}
