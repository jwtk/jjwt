/*
 * Copyright © 2023 jsonwebtoken.io
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

abstract class ReflectionFunction<T, R> implements Function<T, R> {

    public static final String ERR_MSG = "Reflection operation failed. This is likely due to an internal " +
            "implementation programming error.  Please report this to the JJWT development team.  Cause: ";

    protected abstract boolean supports(T input);

    protected abstract R invoke(T input) throws Throwable;

    @Override
    public final R apply(T input) {
        if (supports(input)) {
            try {
                return invoke(input);
            } catch (Throwable throwable) {
                // should never happen if supportsInput is true since that would mean we're using the API incorrectly
                String msg = ERR_MSG + throwable.getMessage();
                throw new IllegalStateException(msg, throwable);
            }
        }
        return null;
    }
}
