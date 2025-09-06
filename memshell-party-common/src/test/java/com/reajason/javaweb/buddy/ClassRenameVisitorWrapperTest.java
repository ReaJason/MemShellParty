package com.reajason.javaweb.buddy;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author ReaJason
 * @since 2025/9/6
 */
class ClassRenameVisitorWrapperTest {

    @Test
    void testFullName() {
        String originalName = "com/apache/injector";
        String newName = "com/hello$Proxy$$Lambda$1";
        assertEquals(newName, originalName.replace(originalName, newName));
    }

    @Test
    void testPrefix() {
        String originalName = "com/apache";
        String newName = "com/hello";
        String className = "com/apache/injector";
        assertEquals("com/hello/injector", className.replace(originalName, newName));
    }

    @Test
    void testWrongClassName() {
        String className = "+/.0o0o00o9o";
        String originalName = className;
        String newName = "com/hello/injector";
        String expected = "com/hello/injector";
        assertEquals(expected, className.replace(originalName, newName));
    }
}