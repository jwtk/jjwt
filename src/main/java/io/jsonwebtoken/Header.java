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

public interface Header extends Map<String,Object> {

    public static final String JWT_TYPE = "JWT";
    public static final String TYPE = "typ";
    public static final String ALGORITHM = "alg";
    public static final String CONTENT_TYPE = "cty";

    public String getType();

    public Header setType(String typ);

    public String getAlgorithm();

    public Header setAlgorithm(String alg);

    public String getContentType();

    public void setContentType(String cty);

}
