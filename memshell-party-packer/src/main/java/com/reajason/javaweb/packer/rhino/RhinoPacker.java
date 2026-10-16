package com.reajason.javaweb.packer.rhino;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;

/**
 * @author ReaJason
 * @since 2025/1/30
 */
public class RhinoPacker implements Packer {

    @Override
    public String pack(ClassPackerConfig config) {
        return Packers.ScriptEngine.getInstance().pack(config);
    }
}
