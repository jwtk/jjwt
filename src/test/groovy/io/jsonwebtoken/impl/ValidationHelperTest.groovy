/*
 * Copyright (C) 2015 jsonwebtoken.io
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
package io.jsonwebtoken.impl

import io.jsonwebtoken.Claims
import org.junit.Test
import static org.junit.Assert.*



class ValidationHelperTest {

    @Test
    void testTokenIsExpired() {
        
        // given
		def Date recent = new Date(System.currentTimeMillis() - 1)
		def Claims claims = new DefaultClaims()
		claims.setExpiration(recent)

		// when
		def boolean expired = ValidationHelper.isExpired(claims)

		// then
		assertTrue expired;
    }
	
	
	@Test
	void testTokenIsNotExpired() {
		
		// given
		def Date future = new Date(System.currentTimeMillis() + 100000)
		def Claims claims = new DefaultClaims()
		claims.setExpiration(future)

		// when
		def boolean expired = ValidationHelper.isExpired(claims)

		// then
		assertFalse expired;
	}
	
	
	@Test
	void testTokenIsPremature() {
		
		// given
		def Date future = new Date(System.currentTimeMillis() + 100000)
		def Claims claims = new DefaultClaims()
		claims.setNotBefore(future)

		// when
		def boolean premature = ValidationHelper.isPremature(claims)

		// then
		assertTrue premature;
	}

	@Test
	void testTokenIsNotPremature() {
		
		// given
		def Date recent = new Date(System.currentTimeMillis() - 1)
		def Claims claims = new DefaultClaims()
		claims.setNotBefore(recent)

		// when
		def boolean premature = ValidationHelper.isPremature(claims)

		// then
		assertFalse premature;
	}
}
