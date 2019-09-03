package io.jsonwebtoken.lang;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.Timeout;

public class AssertTest {

    @Rule public final ExpectedException thrown = ExpectedException.none();

    @Rule public final Timeout globalTimeout = new Timeout(10000);

    // Test written by Diffblue Cover.
    @Test
    public void doesNotContainInputNotNullNotNullNotNullOutputIllegalArgumentException() {

        // Arrange
        final String textToSearch = "1234";
        final String substring = "2";
        final String message = ",";

        // Act
        thrown.expect(IllegalArgumentException.class);
        io.jsonwebtoken.lang.Assert.doesNotContain(textToSearch, substring, message);

        // The method is not expected to return due to exception thrown
    }

    // Test written by Diffblue Cover.
    @Test
    public void doesNotContainInputNotNullNotNullOutputIllegalArgumentException() {

        // Arrange
        final String textToSearch = "a\'b\'c";
        final String substring = "a\'b\'c";

        // Act
        thrown.expect(IllegalArgumentException.class);
        io.jsonwebtoken.lang.Assert.doesNotContain(textToSearch, substring);

        // The method is not expected to return due to exception thrown
    }

    // Test written by Diffblue Cover.
    @Test
    public void hasLengthInputNullOutputIllegalArgumentException() {

        // Arrange
        final String text = null;

        // Act
        thrown.expect(IllegalArgumentException.class);
        io.jsonwebtoken.lang.Assert.hasLength(text);

        // The method is not expected to return due to exception thrown
    }

    // Test written by Diffblue Cover.
    @Test
    public void hasTextInputNullNullOutputIllegalArgumentException() {

        // Arrange
        final String text = null;
        final String message = null;

        // Act
        thrown.expect(IllegalArgumentException.class);
        io.jsonwebtoken.lang.Assert.hasText(text, message);

        // The method is not expected to return due to exception thrown
    }

    // Test written by Diffblue Cover.
    @Test
    public void isAssignableInputNullNullNotNullOutputIllegalArgumentException() {

        // Arrange
        final Class superType = null;
        final Class subType = null;
        final String message = "3";

        // Act
        thrown.expect(IllegalArgumentException.class);
        io.jsonwebtoken.lang.Assert.isAssignable(superType, subType, message);

        // The method is not expected to return due to exception thrown
    }

    // Test written by Diffblue Cover.
    @Test
    public void isAssignableInputNullNullOutputIllegalArgumentException() {

        // Arrange
        final Class superType = null;
        final Class subType = null;

        // Act
        thrown.expect(IllegalArgumentException.class);
        io.jsonwebtoken.lang.Assert.isAssignable(superType, subType);

        // The method is not expected to return due to exception thrown
    }

    // Test written by Diffblue Cover.
    @Test
    public void isInstanceOfInputNullNullNotNullOutputIllegalArgumentException() {

        // Arrange
        final Class type = null;
        final Object obj = null;
        final String message = "3";

        // Act
        thrown.expect(IllegalArgumentException.class);
        io.jsonwebtoken.lang.Assert.isInstanceOf(type, obj, message);

        // The method is not expected to return due to exception thrown
    }

    // Test written by Diffblue Cover.
    @Test
    public void isInstanceOfInputNullNullOutputIllegalArgumentException() {

        // Arrange
        final Class clazz = null;
        final Object obj = null;

        // Act
        thrown.expect(IllegalArgumentException.class);
        io.jsonwebtoken.lang.Assert.isInstanceOf(clazz, obj);

        // The method is not expected to return due to exception thrown
    }

    // Test written by Diffblue Cover.
    @Test
    public void isNullInputZeroNotNullOutputIllegalArgumentException() {

        // Arrange
        final Object object = 0;
        final String message = "3";

        // Act
        thrown.expect(IllegalArgumentException.class);
        io.jsonwebtoken.lang.Assert.isNull(object, message);

        // The method is not expected to return due to exception thrown
    }

    // Test written by Diffblue Cover.
    @Test
    public void isTrueInputFalseNotNullOutputIllegalArgumentException() {

        // Arrange
        final boolean expression = false;
        final String message = ",";

        // Act
        thrown.expect(IllegalArgumentException.class);
        io.jsonwebtoken.lang.Assert.isTrue(expression, message);

        // The method is not expected to return due to exception thrown
    }

    // Test written by Diffblue Cover.

    @Test
    public void noNullElementsInput1NotNullOutputIllegalArgumentException() {

        // Arrange
        final Object[] array = {null};
        final String message = "3";

        // Act
        thrown.expect(IllegalArgumentException.class);
        io.jsonwebtoken.lang.Assert.noNullElements(array, message);

        // The method is not expected to return due to exception thrown
    }

    // Test written by Diffblue Cover.
    @Test
    public void notNullInputNullNotNullOutputIllegalArgumentException() {

        // Arrange
        final Object object = null;
        final String message = "A1B2C3";

        // Act
        thrown.expect(IllegalArgumentException.class);
        io.jsonwebtoken.lang.Assert.notNull(object, message);

        // The method is not expected to return due to exception thrown
    }

    // Test written by Diffblue Cover.
    @Test
    public void notNullInputNullOutputIllegalArgumentException() {

        // Arrange
        final Object object = null;

        // Act
        thrown.expect(IllegalArgumentException.class);
        io.jsonwebtoken.lang.Assert.notNull(object);

        // The method is not expected to return due to exception thrown
    }

    // Test written by Diffblue Cover.
    @Test
    public void stateInputFalseNotNullOutputIllegalStateException() {

        // Arrange
        final boolean expression = false;
        final String message = "3";

        // Act
        thrown.expect(IllegalStateException.class);
        io.jsonwebtoken.lang.Assert.state(expression, message);

        // The method is not expected to return due to exception thrown
    }
}
