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
package io.jsonwebtoken.impl;

import io.jsonwebtoken.JwsHeader;

import java.util.Map;

public class DefaultJwsHeader extends DefaultHeader implements JwsHeader {

    public DefaultJwsHeader() {
        super();
    }

    public DefaultJwsHeader(Map<String, Object> map) {
        super(map);
    }

    @Override
    public String getAlgorithm() {
        return getString(ALGORITHM);
    }

    @Override
    public JwsHeader setAlgorithm(String alg) {
        setValue(ALGORITHM, alg);
        return this;
    }

    @Override
    public String getKeyId() {
        return getString(KEY_ID);
    }

    @Override
    public JwsHeader setKeyId(String kid) {
        setValue(KEY_ID, kid);
        return this;
    }

}
