package io.jsonwebtoken.it.unsigned;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwt;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;


public class UnsignedJwtCreatorTest {

    @Test
    public void testUnsignedJwt() {
        // given:
        final UnsignedJwtCreator jwtCreator = new UnsignedJwtCreator();
        final String jwtString = jwtCreator.create();

        // when
        final Jwt<Header, Claims> readBackJws = jwtCreator.read(jwtString);

        // then
        final Claims jwtBody = readBackJws.getPayload();
        assertEquals("jjwt-0", jwtBody.getId());
        assertEquals("jjwt", jwtBody.getSubject());
        assertTrue(jwtBody.get("roles", List.class).contains("admin"));
    }

}
