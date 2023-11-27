package io.jsonwebtoken.jackson.io;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.UntypedObjectDeserializer;

import java.io.IOException;
import java.util.Map;

/**
 * A Jackson {@link com.fasterxml.jackson.databind.JsonDeserializer JsonDeserializer}, that will convert claim
 * values to types based on {@code claimTypeMap}.
 */
class ClaimTypeDeserializer extends UntypedObjectDeserializer {

    private final Map<String, Class<?>> claimTypeMap;

    ClaimTypeDeserializer(Map<String, Class<?>> claimTypeMap) {
        super(null, null);
        this.claimTypeMap = claimTypeMap;
    }

    @Override
    public Object deserialize(JsonParser parser, DeserializationContext context) throws IOException {
        String name = parser.currentName();
        if (claimTypeMap != null && name != null && claimTypeMap.containsKey(name)) {
            Class<?> type = claimTypeMap.get(name);
            //noinspection resource
            return parser.readValueAsTree().traverse(parser.getCodec()).readValueAs(type);
        }
        return super.deserialize(parser, context);
    }
}
