/*
 * Copyright (C) 2021 jsonwebtoken.io
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
package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.Message;

class DefaultMessage<T> implements Message<T> {

    private final T payload;

    DefaultMessage(T payload) {
        this.payload = Assert.notNull(payload, "payload cannot be null.");
        if (payload instanceof byte[]) {
            assertBytePayload((byte[])payload);
        }
    }
    protected void assertBytePayload(byte[] payload) {
        Assert.notEmpty(payload, "payload byte array cannot be null or empty.");
    }

    @Override
    public T getPayload() {
        return payload;
    }
}
