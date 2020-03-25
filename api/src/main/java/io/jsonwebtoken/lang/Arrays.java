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
 * @since 0.6
 */
public final class Arrays {

    private Arrays(){} //prevent instantiation

    public static int length(byte[] bytes) {
        return bytes != null ? bytes.length : 0;
    }

    public static byte[] clean(byte[] bytes) {
        return length(bytes) > 0 ? bytes : null;
    }
}
