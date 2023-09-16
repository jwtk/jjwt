/*
 * Copyright © 2020 jsonwebtoken.io
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

public interface Converter<A, B> {

    /**
     * Converts the specified (Java idiomatic type) value to the canonical RFC-required data type.
     *
     * @param a the preferred idiomatic value
     * @return the canonical RFC-required data type value.
     */
    B applyTo(A a);

    /**
     * Converts the specified canonical (RFC-compliant data type) value to the preferred Java idiomatic type.
     *
     * @param b the canonical value to convert
     * @return the preferred Java idiomatic type value.
     */
    A applyFrom(B b);
}
