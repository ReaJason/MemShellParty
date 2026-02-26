package com.reajason.javaweb.packer.groovy;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;

/**
 * @author ReaJason
 * @since 2024/12/13
 */
public class GroovyPacker implements Packer {
    @Override
    public String pack(ClassPackerConfig classPackerConfig) {
        return Packers.GroovyClassDefiner.getInstance().pack(classPackerConfig);
    }
}
