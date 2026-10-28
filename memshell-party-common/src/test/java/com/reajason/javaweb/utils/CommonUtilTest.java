package com.reajason.javaweb.utils;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author ReaJason
 */
class CommonUtilTest {

    @Test
    void injectorClassNameUsesWordSampler() {
        for (int i = 0; i < 200; i++) {
            String className = CommonUtil.generateInjectorClassName();
            assertTrue(className.matches("[a-z][a-z0-9.]*\\.[A-Z][A-Za-z0-9]*Utils"), className);
            String packageName = className.substring(0, className.lastIndexOf('.'));
            assertEquals(packageName.toLowerCase(), packageName, className);
        }
    }

    @Test
    void generatedClassNameIsWordBased() {
        for (int i = 0; i < 200; i++) {
            String className = CommonUtil.generateClassName();
            assertTrue(className.matches("[a-z][a-z0-9.]*\\.[A-Z][A-Za-z0-9]*Handler"), className);
        }
    }

    @Test
    void generatedRandomPackageUsesWordSampler() {
        for (int i = 0; i < 200; i++) {
            String packageName = CommonUtil.generateRandomPackage();
            assertTrue(packageName.matches("[a-z][a-z0-9.]*"), packageName);
            assertFalse(packageName.startsWith("com.reajason"), packageName);
            String[] segments = packageName.split("\\.");
            assertTrue(segments.length >= 4, packageName);
        }
    }
}
