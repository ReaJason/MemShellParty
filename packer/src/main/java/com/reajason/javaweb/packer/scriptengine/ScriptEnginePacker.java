package com.reajason.javaweb.packer.scriptengine;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;

/**
 * @author ReaJason
 * @since 2024/12/3
 */
public class ScriptEnginePacker implements Packer {
    @Override
    public String pack(ClassPackerConfig classPackerConfig) {
        return Packers.DefaultScriptEngine.getInstance().pack(classPackerConfig);
    }
}
