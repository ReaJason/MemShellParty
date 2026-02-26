package com.reajason.javaweb.packer.translet;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;

/**
 * @author ReaJason
 * @since 2025/11/19
 */
public class AbstractTransletPacker implements Packer {
    @Override
    public String pack(ClassPackerConfig classPackerConfig) {
        return Packers.JDKAbstractTransletPacker.getInstance().pack(classPackerConfig);
    }
}
