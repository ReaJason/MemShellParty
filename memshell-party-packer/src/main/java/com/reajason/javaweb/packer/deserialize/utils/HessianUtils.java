package com.reajason.javaweb.packer.deserialize.utils;

import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.List;

/**
 * @author ReaJason
 * @since 2025/2/19
 */
public class HessianUtils {

    public static HashMap<?, ?> toMap(List<?> objs) throws Exception {
        HashMap<?, ?> s = new HashMap<>(8);
        Reflections.setFieldValue(s, "size", objs.size());
        Class<?> nodeC;
        try {
            nodeC = Class.forName("java.util.HashMap$Node");
        } catch (ClassNotFoundException var6) {
            nodeC = Class.forName("java.util.HashMap$Entry");
        }
        Constructor<?> nodeCons = nodeC.getDeclaredConstructor(Integer.TYPE, Object.class, Object.class, nodeC);
        nodeCons.setAccessible(true);
        Object tbl = Array.newInstance(nodeC, objs.size());
        for (int i = 0; i < objs.size(); i++) {
            Array.set(tbl, i, nodeCons.newInstance(0, objs.get(i), objs.get(i), null));
        }
        Reflections.setFieldValue(s, "table", tbl);
        return s;
    }
}
