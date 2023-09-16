/*
 * Copyright © 2022 jsonwebtoken.io
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

import io.jsonwebtoken.lang.Assert;

import java.util.concurrent.atomic.AtomicInteger;

public class PositiveIntegerConverter implements Converter<Integer, Object> {

    public static final PositiveIntegerConverter INSTANCE = new PositiveIntegerConverter();

    @Override
    public Object applyTo(Integer integer) {
        return integer;
    }

    @Override
    public Integer applyFrom(Object o) {
        Assert.notNull(o, "Argument cannot be null.");
        int i;
        if (o instanceof Byte || o instanceof Short || o instanceof Integer || o instanceof AtomicInteger) {
            i = ((Number) o).intValue();
        } else {  // could be Long, AtomicLong, Float, Decimal, BigInteger, BigDecimal, String, etc., all of which
            // may not be accurately converted into an Integer, either due to overflow or fractional values.  The
            // easiest way to account for all of them is to parse the string value as an int instead of testing all
            // the types:
            String sval = String.valueOf(o);
            try {
                i = Integer.parseInt(sval);
            } catch (NumberFormatException e) {
                String msg = "Value cannot be represented as a java.lang.Integer.";
                throw new IllegalArgumentException(msg, e);
            }
        }
        if (i <= 0) {
            String msg = "Value must be a positive integer.";
            throw new IllegalArgumentException(msg);
        }
        return i;
    }
}
