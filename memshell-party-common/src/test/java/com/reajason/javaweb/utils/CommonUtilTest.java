package com.reajason.javaweb.utils;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author ReaJason
 */
class CommonUtilTest {

    private static final String[] FIXED_PACKAGE_PREFIXES = {
            "org.springframework.foundation.support",
            "org.apache.platform.runtime",
            "org.apache.commons.foundation.internal",
            "com.fasterxml.jackson.runtime.support",
            "com.google.gson.platform.internal",
            "ch.qos.logback.foundation.runtime"
    };

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
    void generatedNamesUseLongUncommonPackagePrefix() {
        for (int i = 0; i < 200; i++) {
            assertLongUncommonPrefix(CommonUtil.generateClassName());
            assertLongUncommonPrefix(CommonUtil.generateInjectorClassName());
        }
    }

    private static void assertLongUncommonPrefix(String className) {
        boolean matched = false;
        for (String prefix : FIXED_PACKAGE_PREFIXES) {
            if (className.startsWith(prefix + ".")) {
                matched = true;
                break;
            }
        }
        assertTrue(matched, className);
        String packageName = className.substring(0, className.lastIndexOf('.'));
        assertTrue(packageName.split("\\.").length >= 4, className);
    }
}
