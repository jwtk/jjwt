package io.jsonwebtoken.impl;

import org.junit.Test;

import static junit.framework.Assert.assertTrue;
import static junit.framework.TestCase.assertEquals;

/**
 * Java specific test to ensure we don't hit Groovy's DefaultGroovyMethods
 */
public class JavaJwtMapTest
{

  @Test
  public void testEquals() throws Exception
  {
    JwtMap jwtMap1 = new JwtMap();
    jwtMap1.put("a", "a");

    JwtMap jwtMap2 = new JwtMap();
    jwtMap2.put("a", "a");

    assertEquals(jwtMap1, jwtMap2);
  }

  @Test
  public void testHashCode() throws Exception
  {
    JwtMap jwtMap = new JwtMap();
    int hashCodeEmpty = jwtMap.hashCode();

    jwtMap.put("a", "b");
    int hashCodeNonEmpty = jwtMap.hashCode();
    assertTrue(hashCodeEmpty != hashCodeNonEmpty);

    int identityHash = System.identityHashCode(jwtMap);
    assertTrue(hashCodeNonEmpty != identityHash);
  }
}
