package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.CurveId;
import io.jsonwebtoken.security.CurveIds;
import io.jsonwebtoken.security.EcJwk;
import io.jsonwebtoken.security.MalformedKeyException;

@SuppressWarnings("unchecked")
class AbstractEcJwk<T extends EcJwk> extends AbstractJwk<T> implements EcJwk<T> {

    static final String TYPE_VALUE = "EC";
    static final String CURVE_ID = "crv";
    static final String X = "x";
    static final String Y = "y";

    AbstractEcJwk() {
        super(TYPE_VALUE);
    }

    @Override
    public CurveId getCurveId() {
        Object val = get(CURVE_ID);
        if (val == null) {
            return null;
        }
        if (val instanceof CurveId) {
            return (CurveId) val;
        }
        if (val instanceof String) {
            CurveId id = CurveIds.forValue((String) val);
            setCurveId(id); //replace string with type safe value
            return id;
        }
        throw new MalformedKeyException("EC JWK 'crv' value must be an CurveId or a String. Value has type: " +
            val.getClass().getName());
    }

    @Override
    public T setCurveId(CurveId curveId) {
        return setRequiredValue(CURVE_ID, curveId, "curve id");
    }

    @Override
    public String getX() {
        return getString(X);
    }

    @Override
    public T setX(String x) {
        return setRequiredValue(X, x, "x coordinate");
    }

    @Override
    public String getY() {
        return getString(Y);
    }

    @Override
    public T setY(String y) {
        y = Strings.clean(y);
        setValue(Y, y);
        return (T) this;
    }
}
