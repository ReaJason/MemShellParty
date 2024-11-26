package com.reajason.javaweb.godzilla;

import com.reajason.javaweb.util.ClassUtils;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author ReaJason
 * @since 2024/11/26
 */
class GodzillaManagerTest {

    @Test
    void generateGodzilla() {
        byte[] bytes = GodzillaManager.generateGodzilla();
        Object o = ClassUtils.newInstance(bytes);
        System.out.println(o.getClass().getName());
        assertNotNull(o);
    }
}