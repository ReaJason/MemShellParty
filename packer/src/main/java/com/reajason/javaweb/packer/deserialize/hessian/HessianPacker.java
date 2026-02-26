package com.reajason.javaweb.packer.deserialize.hessian;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;

/**
 * @author ReaJason
 * @since 2025/2/20
 */
public class HessianPacker implements Packer {
    @Override
    public String pack(ClassPackerConfig classPackerConfig) {
        return Packers.HessianXSLTScriptEngine.getInstance().pack(classPackerConfig);
    }
}
