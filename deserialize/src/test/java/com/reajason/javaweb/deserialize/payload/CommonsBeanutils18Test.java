package com.reajason.javaweb.deserialize.payload;

import com.reajason.javaweb.deserialize.utils.Reflections;
import lombok.SneakyThrows;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.description.modifier.FieldManifestation;
import net.bytebuddy.description.modifier.Ownership;
import net.bytebuddy.description.modifier.Visibility;
import net.bytebuddy.dynamic.loading.ClassLoadingStrategy;
import org.junit.jupiter.api.Test;

import java.net.URL;
import java.net.URLClassLoader;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author ReaJason
 * @since 2025/2/17
 */
class CommonsBeanutils18Test {

    @Test
    @SneakyThrows
    void test() {
        Object object = new ByteBuddy()
                .redefine(Class.forName("org.apache.commons.beanutils.BeanComparator"))
                .defineField("serialVersionUID", long.class, Visibility.PRIVATE, Ownership.STATIC, FieldManifestation.FINAL)
                .value(-2044202215314119608L)
                .make().load(new URLClassLoader(new URL[]{}), ClassLoadingStrategy.Default.INJECTION).getLoaded().newInstance();
        assertEquals(-2044202215314119608L, Reflections.getFieldValue(object, "serialVersionUID"));
    }

}