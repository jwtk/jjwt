module io.jsonwebtoken.jjwt.ext.orgjson {
    requires transitive org.json;
    requires io.jsonwebtoken.jjwt.api;

    exports io.jsonwebtoken.orgjson.io;

    provides io.jsonwebtoken.io.Deserializer with io.jsonwebtoken.orgjson.io.OrgJsonDeserializer;
    provides io.jsonwebtoken.io.Serializer with io.jsonwebtoken.orgjson.io.OrgJsonSerializer;
}
