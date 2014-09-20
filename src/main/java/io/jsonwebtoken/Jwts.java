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

import io.jsonwebtoken.impl.DefaultClaims;
import io.jsonwebtoken.impl.DefaultHeader;
import io.jsonwebtoken.impl.DefaultJwsHeader;
import io.jsonwebtoken.impl.DefaultJwtBuilder;
import io.jsonwebtoken.impl.DefaultJwtParser;

import java.util.Map;

/**
 * Factory class useful for creating instances of JWT interfaces.  Using this factory class can be a good
 * alternative to tightly coupling your code to implementation classes.
 *
 * @since 0.1
 */
public class Jwts {

    public static Header header() {
        return new DefaultHeader();
    }

    public static Header header(Map<String,Object> header) {
        return new DefaultHeader(header);
    }

    public static JwsHeader jwsHeader() {
        return new DefaultJwsHeader();
    }

    public static JwsHeader jwsHeader(Map<String,Object> header) {
        return new DefaultJwsHeader(header);
    }

    public static Claims claims() {
        return new DefaultClaims();
    }

    public static Claims claims(Map<String, Object> claims) {
        if (claims == null) {
            return claims();
        }
        return new DefaultClaims(claims);
    }

    public static JwtParser parser() {
        return new DefaultJwtParser();
    }

    public static JwtBuilder builder() {
        return new DefaultJwtBuilder();
    }
}
