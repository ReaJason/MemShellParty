package com.reajason.javaweb.packer.h2;

import com.reajason.javaweb.packer.ClassPackerConfig;
import org.junit.jupiter.api.Test;

import javax.script.Compilable;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * @author ReaJason
 * @since 2025/6/28
 */
class H2JSPackerTest {

    @Test
    void pack() throws Exception {
        ClassPackerConfig classPackerConfig = new ClassPackerConfig();
        classPackerConfig.setClassName("com.reajason.javaweb.ErrorAbcdHandler");
        classPackerConfig.setClassBytesBase64Str("aGVsbG8=");
        String url = new H2JSPacker().pack(classPackerConfig);
        String js = extractJs(url);
        assertFalse(js.contains("$$"), "dollar-quoted body should not contain $$: " + js);
        compileJs(js);
        assertClassName(js, "com.reajason.javaweb.ErrorAbcdHandler");
    }

    @Test
    void packClassNameWithLambdaSuffix() throws Exception {
        ClassPackerConfig classPackerConfig = new ClassPackerConfig();
        classPackerConfig.setClassName("le.gso.SzyHj.SOAPUtils$Proxy0$$Lambda$1");
        classPackerConfig.setClassBytesBase64Str("aGVsbG8=");
        String url = new H2JSPacker().pack(classPackerConfig);
        String js = extractJs(url);
        assertFalse(js.contains("$$"), "dollar-quoted body should not contain $$: " + js);
        compileJs(js);
        assertClassName(js, "le.gso.SzyHj.SOAPUtils$Proxy0$$Lambda$1");
    }

    /**
     * 提取 $$..$$ 美元引用字符串中的 JS 源码，并还原 H2 连接串层面的 \; 转义
     */
    private String extractJs(String url) {
        String body = url.substring(url.indexOf("$$") + 2, url.lastIndexOf("$$"));
        return body.substring("//javascript\n".length()).replace("\\;", ";");
    }

    /**
     * 只解析不执行，验证拼接后的 JS 语法仍然合法
     */
    private void compileJs(String js) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        assertNotNull(engine, "need a JDK with Nashorn to run this test");
        ((Compilable) engine).compile(js);
    }

    /**
     * 只执行 className 赋值语句，验证 $$ 拆分成 "$"+"$" 后仍能还原出原类名
     */
    private void assertClassName(String js, String expectedClassName) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        int start = js.indexOf("var className");
        if (start < 0) {
            throw new AssertionError("className assignment not found in: " + js);
        }
        engine.eval(js.substring(start, js.indexOf(';', start)));
        assertEquals(expectedClassName, engine.get("className"));
    }
}
