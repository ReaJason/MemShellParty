package com.reajason.javaweb.packer;

import com.reajason.javaweb.memshell.config.ObfuscationConfig;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PackerConstraintsTest {

    @Test
    void enforcesExactSpringExpressionPackage() {
        PackerConstraints constraints = new PackerConstraints("test", new Packer() {
            @Override
            public boolean requiresSpringExpressionPackage() {
                return true;
            }
        });

        String generated = constraints.enforceClassName("com.example.Payload");
        assertTrue(PackerSupport.isSpringExpressionClassName(generated), generated);
        assertEquals("org.springframework.expression.Payload",
                constraints.enforceClassName("org.springframework.expression.Payload"));
        assertTrue(PackerSupport.isSpringExpressionClassName(
                constraints.enforceClassName("org.springframework.expression.sub.Payload")));
    }

    @Test
    void disablesObfuscationBeforeSpelPacking() {
        PackerConstraints constraints = new PackerConstraints("test", new Packer() {
            @Override
            public boolean transportedAsSpelExpression() {
                return true;
            }
        });
        ObfuscationConfig obfuscation = ObfuscationConfig.enabled();

        constraints.constrainObfuscation(obfuscation);
        constraints.constrainObfuscation(obfuscation);

        assertFalse(obfuscation.isEnabled());
    }
}
