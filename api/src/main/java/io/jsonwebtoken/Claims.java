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

import java.util.Map;

/**
 * A JWT <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-4">Claims set</a>.
 *
 * <p>This is an immutable JSON map with convenient type-safe getters for JWT standard claim names (all getters
 * are defined in the {@link ClaimsAccessor} superinterface).</p>
 *
 * <p>Additionally, this interface also extends <code>Map&lt;String, Object&gt;</code>, so you can use standard
 * {@code Map} accessor/iterator methods as desired, for example:</p>
 *
 * <blockquote><pre>
 * claims.get("someKey");</pre></blockquote>
 *
 * <p>However, because {@code Claims} instances are immutable, calling any of the map mutation methods
 * (such as {@code Map.}{@link Map#put(Object, Object) put}, etc) will result in a runtime exception.  The
 * {@code Map} interface is implemented specifically for the convenience of working with existing Map-based utilities
 * and APIs.</p>
 *
 * @since 0.1
 */
public interface Claims extends Map<String, Object>, ClaimsAccessor {

    /** JWT {@code Issuer} claims parameter name: <code>"iss"</code> */
    String ISSUER = "iss";

    /** JWT {@code Subject} claims parameter name: <code>"sub"</code> */
    String SUBJECT = "sub";

    /** JWT {@code Audience} claims parameter name: <code>"aud"</code> */
    String AUDIENCE = "aud";

    /** JWT {@code Expiration} claims parameter name: <code>"exp"</code> */
    String EXPIRATION = "exp";

    /** JWT {@code Not Before} claims parameter name: <code>"nbf"</code> */
    String NOT_BEFORE = "nbf";

    /** JWT {@code Issued At} claims parameter name: <code>"iat"</code> */
    String ISSUED_AT = "iat";

    /** JWT {@code JWT ID} claims parameter name: <code>"jti"</code> */
    String ID = "jti";
}
