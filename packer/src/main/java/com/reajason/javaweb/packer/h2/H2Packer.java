package com.reajason.javaweb.packer.h2;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;

/**
 * @author ReaJason
 * @since 2025/6/28
 */
public class H2Packer implements Packer {
    @Override
    public String pack(ClassPackerConfig classPackerConfig) {
        return Packers.H2Javac.getInstance().pack(classPackerConfig);
    }
}
