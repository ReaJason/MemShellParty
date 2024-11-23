package com.reajason.javaweb.memsell;

import com.reajason.javaweb.memsell.tomcat.injector.TomcatFilterInjector;
import com.reajason.javaweb.util.ClassUtils;
import com.reajason.javaweb.util.CommonUtil;
import lombok.SneakyThrows;
import me.gv7.woodpecker.tools.common.FileUtil;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
class InjectorGeneratorTest {

    InjectorGenerator injectorGenerator = new InjectorGenerator();

    @Test
    @SneakyThrows
    void generateGodzilla() {
        byte[] shellBytes = IOUtils.resourceToByteArray("/CommonFilter.class");
        String shellClassName = "org.apache.utils.CommonFilter";
        String injectClassName = "org.junit.jupiter.InjectUtil";
        byte[] bytes = injectorGenerator.generate(TomcatFilterInjector.class, injectClassName, shellClassName, shellBytes, "/*");
        Object obj = ClassUtils.newInstance(bytes);
        assertEquals(injectClassName, obj.getClass().getName());
        assertEquals(shellClassName, ClassUtils.invokeMethod(obj, "getClassName", null, null).toString());
        assertEquals("/*", ClassUtils.invokeMethod(obj, "getUrlPattern", null, null).toString());
        assertEquals(Base64.encodeBase64String(CommonUtil.gzipCompress(shellBytes)).replace(System.lineSeparator(), ""),
                ClassUtils.invokeMethod(obj, "getBase64String", null, null).toString());

//        Object filter = ClassUtils.invokeMethod(obj, "getFilter", new Class[]{Object.class}, new Object[]{null});
//        assertEquals(shellClassName, filter.getClass().getName());
//
//        FileUtil.writeFile("InjectUtil.class", bytes);
        System.out.println(Base64.encodeBase64String(bytes));
    }
}