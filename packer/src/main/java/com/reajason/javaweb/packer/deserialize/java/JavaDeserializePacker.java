package com.reajason.javaweb.packer.deserialize.java;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;

/**
 * @author ReaJason
 * @since 2024/12/10
 */
public class JavaDeserializePacker implements Packer {
    @Override
    public String pack(ClassPackerConfig classPackerConfig) {
        return Packers.JavaCommonsBeanutils19.getInstance().pack(classPackerConfig);
    }
}
