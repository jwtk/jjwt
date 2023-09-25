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
package io.jsonwebtoken.impl.io;

import io.jsonwebtoken.io.DecodingException;
import io.jsonwebtoken.lang.Assert;

import java.io.InputStream;

public class DecodingInputStream extends FilteredInputStream {

    private final String codecName;
    private final String name;

    public DecodingInputStream(InputStream in, String codecName, String name) {
        super(in);
        this.codecName = Assert.hasText(codecName, "codecName cannot be null or empty.");
        this.name = Assert.hasText(name, "Name cannot be null or empty.");
    }

    @Override
    protected void onThrowable(Throwable t) {
        String msg = "Unable to " + this.codecName + "-decode " + this.name + ": " + t.getMessage();
        throw new DecodingException(msg, t);
    }
}
