package com.reajason.javaweb.packer.xmldecoder;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;

/**
 * @author ReaJason
 * @since 2025/7/22
 */
public class XMLDecoderPacker implements Packer {
    @Override
    public String pack(ClassPackerConfig classPackerConfig) {
        return Packers.XMLDecoderScriptEngine.getInstance().pack(classPackerConfig);
    }
}
