/*
 * Copyright (C) 2019 jsonwebtoken.io
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
package io.jsonwebtoken

import com.fasterxml.jackson.annotation.JsonTypeInfo
import com.fasterxml.jackson.databind.ObjectMapper
import io.jsonwebtoken.jackson.io.JacksonDeserializer
import io.jsonwebtoken.jackson.io.JacksonSerializer
import io.jsonwebtoken.io.Decoders
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertNotNull
import static org.junit.Assert.assertTrue

class CustomObjectDeserializationTest {

    /**
     * Test parsing without and then with a custom deserializer. Ensures custom type is parsed from claims
     */
    @Test
    void testCustomObjectDeserialization() {

        CustomBean customBean = new CustomBean()
        customBean.key1 = "value1"
        customBean.key2 = 42

        String jwtString = Jwts.builder().claim("cust", customBean).compact()

        String payload = new String(Decoders.BASE64URL.decode(jwtString.split('\\.')[1]), 'UTF-8')
        assertEquals '{"cust":{"key1":"value1","key2":42}}', payload

        // no custom deserialization, object is a map
        Jwt<Header, Claims> jwt = Jwts.parser().unsecured().build().parseUnsecuredClaims(jwtString)
        assertNotNull jwt
        assertEquals jwt.getPayload().get('cust'), [key1: 'value1', key2: 42]

        // custom type for 'cust' claim
        def des = new JacksonDeserializer([cust: CustomBean])
        jwt = Jwts.parser().unsecured().json(des).build().parseUnsecuredClaims(jwtString)
        assertNotNull jwt
        CustomBean result = jwt.getPayload().get("cust", CustomBean)
        assertEquals customBean, result
    }

    /**
     * Asserts https://github.com/jwtk/jjwt/issues/1065
     */
    @Test
    void testCustomObjectDeserializationWithJsonTypeInfo() {

        ObjectMapper objectMapper = new ObjectMapper()
                .addMixIn(Authority, AuthorityMixin)
        SimpleAuthority authority = new SimpleAuthority('ROLE_ADMIN')

        String jwtString = Jwts.builder()
                .json(new JacksonSerializer(objectMapper))
                .claim('authority', authority)
                .compact()

        String payload = new String(Decoders.BASE64URL.decode(jwtString.split('\\.')[1]), 'UTF-8')
        assertTrue payload.contains('"@class":"io.jsonwebtoken.CustomObjectDeserializationTest$SimpleAuthority"')

        Jwt<Header, Claims> jwt = Jwts.parser()
                .unsecured()
                .json(new JacksonDeserializer(objectMapper, [authority: Authority]))
                .build()
                .parseUnsecuredClaims(jwtString)
        assertEquals authority, jwt.payload.get('authority')
    }

    interface Authority {
        String getAuthority()
    }

    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
    static abstract class AuthorityMixin {
    }

    static class SimpleAuthority implements Authority {
        private String authority

        SimpleAuthority() {
        }

        SimpleAuthority(String authority) {
            this.authority = authority
        }

        String getAuthority() {
            return authority
        }

        void setAuthority(String authority) {
            this.authority = authority
        }

        boolean equals(o) {
            return o instanceof SimpleAuthority && authority == o.authority
        }

        int hashCode() {
            return authority?.hashCode() ?: 0
        }
    }

    static class CustomBean {
        private String key1
        private Integer key2

        String getKey1() {
            return key1
        }

        void setKey1(String key1) {
            this.key1 = key1
        }

        Integer getKey2() {
            return key2
        }

        void setKey2(Integer key2) {
            this.key2 = key2
        }

        boolean equals(o) {
            if (this.is(o)) return true
            if (getClass() != o.class) return false

            CustomBean that = (CustomBean) o

            if (key1 != that.key1) return false
            if (key2 != that.key2) return false

            return true
        }

        int hashCode() {
            int result
            result = (key1 != null ? key1.hashCode() : 0)
            result = 31 * result + (key2 != null ? key2.hashCode() : 0)
            return result
        }
    }
}
