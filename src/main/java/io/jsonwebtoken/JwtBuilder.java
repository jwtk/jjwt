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

import java.security.Key;
import java.util.Map;

public interface JwtBuilder {

    //replaces any existing header with the specified header.
    JwtBuilder setHeader(Header header);

    //replaces current header with specified header
    JwtBuilder setHeader(Map<String,Object> header);

    //appends to any existing header the specified parameters.
    JwtBuilder setHeaderParams(Map<String,Object> params);

    //sets the specified header parameter, overwriting any previous value under the same name.
    JwtBuilder setHeaderParam(String name, Object value);

    JwtBuilder setPayload(String payload);

    JwtBuilder setClaims(Claims claims);

    JwtBuilder setClaims(Map<String,Object> claims);

    JwtBuilder signWith(SignatureAlgorithm alg, byte[] secretKey);

    JwtBuilder signWith(SignatureAlgorithm alg, String base64EncodedSecretKey);

    JwtBuilder signWith(SignatureAlgorithm alg, Key key);

    String compact();
}
