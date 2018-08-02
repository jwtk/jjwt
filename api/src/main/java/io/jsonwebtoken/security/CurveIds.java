package io.jsonwebtoken.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Maps;
import io.jsonwebtoken.lang.Strings;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class CurveIds {

    public static final CurveId P256 = new DefaultCurveId("P-256");
    public static final CurveId P384 = new DefaultCurveId("P-384");
    public static final CurveId P521 = new DefaultCurveId("P-521"); // yes, this is supposed to be 521 and not 512

    private static final Map<String, CurveId> STANDARD_IDS = Collections.unmodifiableMap(Maps
        .of(P256.toString(), P256)
        .and(P384.toString(), P384)
        .and(P521.toString(), P521)
        .build());

    private static final Set<CurveId> STANDARD_IDS_SET =
        Collections.unmodifiableSet(new LinkedHashSet<>(STANDARD_IDS.values()));

    public static Set<CurveId> values() {
        return STANDARD_IDS_SET;
    }

    public static boolean isStandard(CurveId curveId) {
        return curveId != null && STANDARD_IDS.containsKey(curveId.toString());
    }

    public static CurveId forValue(String value) {
        value = Strings.clean(value);
        Assert.hasText(value, "value argument cannot be null or empty.");
        CurveId std = STANDARD_IDS.get(value);
        return std != null ? std : new DefaultCurveId(value);
    }
}
