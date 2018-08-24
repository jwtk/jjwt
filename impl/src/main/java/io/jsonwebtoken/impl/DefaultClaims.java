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

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.RequiredTypeException;

import java.util.Date;
import java.util.Map;

public class DefaultClaims extends JwtMap implements Claims {

    public DefaultClaims() {
        super();
    }

    public DefaultClaims(Map<String, Object> map) {
        super(map);
    }

    @Override
    public String getIssuer() {
        return getString(ISSUER);
    }

    @Override
    public Claims setIssuer(String iss) {
        setValue(ISSUER, iss);
        return this;
    }

    @Override
    public String getSubject() {
        return getString(SUBJECT);
    }

    @Override
    public Claims setSubject(String sub) {
        setValue(SUBJECT, sub);
        return this;
    }

    @Override
    public String getAudience() {
        return getString(AUDIENCE);
    }

    @Override
    public Claims setAudience(String aud) {
        setValue(AUDIENCE, aud);
        return this;
    }

    @Override
    public Date getExpiration() {
        return get(Claims.EXPIRATION, Date.class);
    }

    @Override
    public Claims setExpiration(Date exp) {
        setDateAsSeconds(Claims.EXPIRATION, exp);
        return this;
    }

    @Override
    public Date getNotBefore() {
        return get(Claims.NOT_BEFORE, Date.class);
    }

    @Override
    public Claims setNotBefore(Date nbf) {
        setDateAsSeconds(Claims.NOT_BEFORE, nbf);
        return this;
    }

    @Override
    public Date getIssuedAt() {
        return get(Claims.ISSUED_AT, Date.class);
    }

    @Override
    public Claims setIssuedAt(Date iat) {
        setDateAsSeconds(Claims.ISSUED_AT, iat);
        return this;
    }

    @Override
    public String getId() {
        return getString(ID);
    }

    @Override
    public Claims setId(String jti) {
        setValue(Claims.ID, jti);
        return this;
    }

    /**
     * @since 0.10.0
     */
    private static boolean isSpecDate(String claimName) {
        return Claims.EXPIRATION.equals(claimName) ||
            Claims.ISSUED_AT.equals(claimName) ||
            Claims.NOT_BEFORE.equals(claimName);
    }

    @Override
    public Object put(String s, Object o) {
        if (o instanceof Date && isSpecDate(s)) { //since 0.10.0
            Date date = (Date)o;
            return setDateAsSeconds(s, date);
        }
        return super.put(s, o);
    }

    @Override
    public <T> T get(String claimName, Class<T> requiredType) {

        Object value = get(claimName);
        if (value == null) {
            return null;
        }

        if (Date.class.equals(requiredType)) {
            if (isSpecDate(claimName)) {
                value = toSpecDate(value, claimName);
            } else {
                value = toDate(value, claimName);
            }
        }

        return castClaimValue(value, requiredType);
    }

    private <T> T castClaimValue(Object value, Class<T> requiredType) {

        if (value instanceof Integer) {
            int intValue = (Integer) value;
            if (requiredType == Long.class) {
                value = (long) intValue;
            } else if (requiredType == Short.class && Short.MIN_VALUE <= intValue && intValue <= Short.MAX_VALUE) {
                value = (short) intValue;
            } else if (requiredType == Byte.class && Byte.MIN_VALUE <= intValue && intValue <= Byte.MAX_VALUE) {
                value = (byte) intValue;
            }
        }

        if (!requiredType.isInstance(value)) {
            throw new RequiredTypeException("Expected value to be of type: " + requiredType + ", but was " + value.getClass());
        }

        return requiredType.cast(value);
    }

    @Override
    public String getAsString(String claimName) {
        return get(claimName, String.class);
    }

    @Override
    public Integer getAsInt(String claimName) {
        return get(claimName, Integer.class);
    }

    @Override
    public Long getAsLong(String claimName) {
        return get(claimName, Long.class);
    }

    @Override
    public Short getAsShort(String claimName) {
        return get(claimName, Short.class);
    }

    @Override
    public Byte getAsByte(String claimName) {
        return get(claimName, Byte.class);
    }

    @Override
    public Date getAsDate(String claimName) {
        return get(claimName, Date.class);
    }

    @Override
    public Boolean getAsBoolean(String claimName) {
        return get(claimName, Boolean.class);
    }

    @Override
    public Map<String, ?> getAsMap(String claimName) {
        return get(claimName, Map.class);
    }
}
