package com.reajason.javaweb.godzilla;

import com.reajason.javaweb.util.ClassUtils;
import org.junit.jupiter.api.Test;

import java.util.Map;

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

    @Test
    void testRestorePayload(){
        String payload = "k2qs7l3%2F4ZZaGyyrfpBQGg0dXGM%2BFVFxzmCWLnyFEgoPSpSjHre4o1HBHTCFnNDX";
        String key = "d8ea7326e6ec5916";
        Map<String, String> map = GodzillaManager.restorePayload(key, payload);
        assertEquals("test", map.get("methodName"));
    }
}