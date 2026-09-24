package com.reajason.javaweb.packer.h2;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;

/**
 * @author ReaJason
 * @since 2025/6/28
 */
public class H2JSPacker implements Packer {
    String template = "jdbc:h2:mem:a;init=CREATE TRIGGER a BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\n{{script}}$$";

    @Override
    public String pack(ClassPackerConfig config) {
        String script = Packers.ScriptEngine.getInstance().pack(config);
        // H2 的 $$..$$ 美元引用字符串没有转义机制，类名（如 SOAPUtils$Proxy0$$Lambda$1）中的
        // $$ 会提前闭合字面量。$$ 只会出现在 JS 的字符串字面量中，拆成 "$"+"$" 拼接即可，
        // 既不残留 $$，又能还原出原类名
        while (script.contains("$$")) {
            script = script.replace("$$", "$\"+\"$");
        }
        return template.replace("{{script}}", script.replaceAll(";", "\\\\;"));
    }
}
