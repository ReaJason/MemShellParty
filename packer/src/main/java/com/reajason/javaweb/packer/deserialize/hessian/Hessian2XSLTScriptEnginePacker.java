package com.reajason.javaweb.packer.deserialize.hessian;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.deserialize.HessianDeserializeGenerator;

/**
 * @author ReaJason
 * @since 2025/2/20
 */
public class Hessian2XSLTScriptEnginePacker implements Packer {
    @Override
    public String pack(ClassPackerConfig config) {
        byte[] injectorBytes = config.getClassBytes();
        String injectorClassName = config.getClassName();
        return HessianDeserializeGenerator.generate2(XSLTScriptEngine.generate(injectorBytes, injectorClassName));
    }
}
