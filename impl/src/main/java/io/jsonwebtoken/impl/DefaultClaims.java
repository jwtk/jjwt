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
import io.jsonwebtoken.ClaimsMutator;
import io.jsonwebtoken.RequiredTypeException;
import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.impl.lang.Fields;
import io.jsonwebtoken.impl.lang.JwtDateConverter;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Registry;

import java.util.Date;
import java.util.Map;

public class DefaultClaims extends JwtMap implements Claims, ClaimsMutator<DefaultClaims> {

    private static final String CONVERSION_ERROR_MSG = "Cannot convert existing claim value of type '%s' to desired type " +
            "'%s'. JJWT only converts simple String, Date, Long, Integer, Short and Byte types automatically. " +
            "Anything more complex is expected to be already converted to your desired type by the JSON Deserializer " +
            "implementation. You may specify a custom Deserializer for a JwtParser with the desired conversion " +
            "configuration via the JwtParserBuilder.deserializeJsonWith() method. " +
            "See https://github.com/jwtk/jjwt#custom-json-processor for more information. If using Jackson, you can " +
            "specify custom claim POJO types as described in https://github.com/jwtk/jjwt#json-jackson-custom-types";

    static final Field<String> ISSUER = Fields.string(Claims.ISSUER, "Issuer");
    static final Field<String> SUBJECT = Fields.string(Claims.SUBJECT, "Subject");
    static final Field<String> AUDIENCE = Fields.string(Claims.AUDIENCE, "Audience");
    static final Field<Date> EXPIRATION = Fields.rfcDate(Claims.EXPIRATION, "Expiration Time");
    static final Field<Date> NOT_BEFORE = Fields.rfcDate(Claims.NOT_BEFORE, "Not Before");
    static final Field<Date> ISSUED_AT = Fields.rfcDate(Claims.ISSUED_AT, "Issued At");
    static final Field<String> JTI = Fields.string(Claims.ID, "JWT ID");

    static final Registry<String, Field<?>> FIELDS = Fields.registry(
            ISSUER, SUBJECT, AUDIENCE, EXPIRATION, NOT_BEFORE, ISSUED_AT, JTI
    );

    public DefaultClaims() {
        super(FIELDS);
    }

    public DefaultClaims(Map<String, ?> map) {
        super(FIELDS, map);
    }

    @Override
    public String getName() {
        return "JWT Claim";
    }

    @Override
    public String getIssuer() {
        return idiomaticGet(ISSUER);
    }

    @Override
    public DefaultClaims setIssuer(String iss) {
        put(ISSUER, iss);
        return this;
    }

    @Override
    public String getSubject() {
        return idiomaticGet(SUBJECT);
    }

    @Override
    public DefaultClaims setSubject(String sub) {
        put(SUBJECT, sub);
        return this;
    }

    @Override
    public String getAudience() {
        return idiomaticGet(AUDIENCE);
    }

    @Override
    public DefaultClaims setAudience(String aud) {
        put(AUDIENCE, aud);
        return this;
    }

    @Override
    public Date getExpiration() {
        return idiomaticGet(EXPIRATION);
    }

    @Override
    public DefaultClaims setExpiration(Date exp) {
        put(EXPIRATION, exp);
        return this;
    }

    @Override
    public Date getNotBefore() {
        return idiomaticGet(NOT_BEFORE);
    }

    @Override
    public DefaultClaims setNotBefore(Date nbf) {
        put(NOT_BEFORE, nbf);
        return this;
    }

    @Override
    public Date getIssuedAt() {
        return idiomaticGet(ISSUED_AT);
    }

    @Override
    public DefaultClaims setIssuedAt(Date iat) {
        put(ISSUED_AT, iat);
        return this;
    }

    @Override
    public String getId() {
        return idiomaticGet(JTI);
    }

    @Override
    public DefaultClaims setId(String jti) {
        put(JTI, jti);
        return this;
    }

    @Override
    public <T> T get(String claimName, Class<T> requiredType) {
        Assert.notNull(requiredType, "requiredType argument cannot be null.");

        Object value = idiomaticGet(claimName);
        if (requiredType.isInstance(value)) {
            return requiredType.cast(value);
        }

        value = get(claimName);
        if (value == null) {
            return null;
        }

        if (Date.class.equals(requiredType)) {
            try {
                value = JwtDateConverter.toDate(value); // NOT specDate logic
            } catch (Exception e) {
                String msg = "Cannot create Date from '" + claimName + "' value '" + value + "'. Cause: " + e.getMessage();
                throw new IllegalArgumentException(msg, e);
            }
        }

        return castClaimValue(claimName, value, requiredType);
    }

    private <T> T castClaimValue(String name, Object value, Class<T> requiredType) {

        if (value instanceof Long || value instanceof Integer || value instanceof Short || value instanceof Byte) {
            long longValue = ((Number) value).longValue();
            if (Long.class.equals(requiredType)) {
                value = longValue;
            } else if (Integer.class.equals(requiredType) && Integer.MIN_VALUE <= longValue && longValue <= Integer.MAX_VALUE) {
                value = (int) longValue;
            } else if (requiredType == Short.class && Short.MIN_VALUE <= longValue && longValue <= Short.MAX_VALUE) {
                value = (short) longValue;
            } else if (requiredType == Byte.class && Byte.MIN_VALUE <= longValue && longValue <= Byte.MAX_VALUE) {
                value = (byte) longValue;
            }
        }

        if (value instanceof Long &&
                (requiredType.equals(Integer.class) || requiredType.equals(Short.class) || requiredType.equals(Byte.class))) {
            String msg = "Claim '" + name + "' value is too large or too small to be represented as a " +
                    requiredType.getName() + " instance (would cause numeric overflow).";
            throw new RequiredTypeException(msg);
        }

        if (!requiredType.isInstance(value)) {
            throw new RequiredTypeException(String.format(CONVERSION_ERROR_MSG, value.getClass(), requiredType));
        }

        return requiredType.cast(value);
    }
}
