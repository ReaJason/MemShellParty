package com.reajason.javaweb.packer;

import com.reajason.javaweb.packer.base64.DefaultBase64Packer;
import com.reajason.javaweb.packer.freemarker.FreemarkerSpELSpringGzipJDK17Packer;
import com.reajason.javaweb.packer.freemarker.FreemarkerSpELSpringGzipPacker;
import com.reajason.javaweb.packer.jxpath.JXPathSpringGzipJDK17Packer;
import com.reajason.javaweb.packer.ognl.OGNLSpringGzipJDK17Packer;
import com.reajason.javaweb.packer.spel.SpELPacker;
import com.reajason.javaweb.packer.spel.SpELScriptEnginePacker;
import com.reajason.javaweb.packer.spel.SpELSpringGzipJDK17Packer;
import com.reajason.javaweb.packer.spel.SpELSpringGzipPacker;
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
class PackerBehaviorTest {

    @Test
    void springGzipJdk17PackersRequireExpressionPackage() {
        assertTrue(new SpELSpringGzipJDK17Packer().requiresSpringExpressionPackage());
        assertTrue(new OGNLSpringGzipJDK17Packer().requiresSpringExpressionPackage());
        assertTrue(new JXPathSpringGzipJDK17Packer().requiresSpringExpressionPackage());
        assertTrue(new FreemarkerSpELSpringGzipJDK17Packer().requiresSpringExpressionPackage());
        assertFalse(new SpELSpringGzipPacker().requiresSpringExpressionPackage());
        assertFalse(new DefaultBase64Packer().requiresSpringExpressionPackage());
    }

    @Test
    void generatedClassNameIsWordBasedAndInExpressionPackage() {
        Packer packer = new SpELSpringGzipJDK17Packer();
        for (int i = 0; i < 100; i++) {
            String className = packer.generateSpringExpressionClassName();
            assertTrue(PackerSupport.isSpringExpressionClassName(className), className);
            assertTrue(className.matches("org\\.springframework\\.expression\\.[A-Z][A-Za-z0-9]*Utils"),
                    className);
        }
    }

    @Test
    void nonSpringPackerCannotGenerateExpressionClassName() {
        assertThrows(IllegalStateException.class,
                () -> new DefaultBase64Packer().generateSpringExpressionClassName());
    }

    @Test
    void spelPackersAreLengthLimitedExpressions() {
        assertTrue(new SpELPacker().transportedAsSpelExpression());
        assertTrue(new SpELScriptEnginePacker().transportedAsSpelExpression());
        assertTrue(new SpELSpringGzipPacker().transportedAsSpelExpression());
        assertTrue(new SpELSpringGzipJDK17Packer().transportedAsSpelExpression());
        assertTrue(new FreemarkerSpELSpringGzipPacker().transportedAsSpelExpression());
        assertTrue(new FreemarkerSpELSpringGzipJDK17Packer().transportedAsSpelExpression());
        assertFalse(new OGNLSpringGzipJDK17Packer().transportedAsSpelExpression());
        assertFalse(new JXPathSpringGzipJDK17Packer().transportedAsSpelExpression());
        assertFalse(new DefaultBase64Packer().transportedAsSpelExpression());
    }
}
