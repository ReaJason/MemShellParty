package com.reajason.javaweb.packer;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * SpringGzipJDK17 系打包器要求类位于 {@code org.springframework.expression} 包下，
 * 类名由词表采样生成。
 *
 * @author ReaJason
 */
class PackersTest {

    @Test
    void springGzipJdk17PackersRequireExpressionPackage() {
        assertTrue(Packers.SpELSpringGzipJDK17.requiresSpringExpressionPackage());
        assertTrue(Packers.OGNLSpringGzipJDK17.requiresSpringExpressionPackage());
        assertTrue(Packers.JXPathSpringGzipJDK17.requiresSpringExpressionPackage());
        assertTrue(Packers.FreemarkerSpELSpringGzipJDK17.requiresSpringExpressionPackage());
        assertFalse(Packers.SpELSpringGzip.requiresSpringExpressionPackage());
        assertFalse(Packers.Base64.requiresSpringExpressionPackage());
    }

    @Test
    void generatedClassNameIsWordBasedAndInExpressionPackage() {
        for (int i = 0; i < 100; i++) {
            String className = Packers.SpELSpringGzipJDK17.generateSpringExpressionClassName();
            assertTrue(Packers.isSpringExpressionClassName(className), className);
            assertTrue(className.matches("org\\.springframework\\.expression\\.[A-Z][A-Za-z0-9]*Utils"),
                    className);
        }
    }

    @Test
    void nonSpringPackerCannotGenerateExpressionClassName() {
        assertThrows(IllegalStateException.class,
                () -> Packers.Base64.generateSpringExpressionClassName());
    }

    @Test
    void spelPackersAreLengthLimitedExpressions() {
        assertTrue(Packers.SpEL.transportedAsSpelExpression());
        assertTrue(Packers.SpELScriptEngine.transportedAsSpelExpression());
        assertTrue(Packers.SpELSpringGzip.transportedAsSpelExpression());
        assertTrue(Packers.SpELSpringGzipJDK17.transportedAsSpelExpression());
        assertTrue(Packers.FreemarkerSpELSpringGzip.transportedAsSpelExpression());
        assertTrue(Packers.FreemarkerSpELSpringGzipJDK17.transportedAsSpelExpression());
        assertFalse(Packers.OGNLSpringGzipJDK17.transportedAsSpelExpression());
        assertFalse(Packers.JXPathSpringGzipJDK17.transportedAsSpelExpression());
        assertFalse(Packers.Base64.transportedAsSpelExpression());
    }
}
