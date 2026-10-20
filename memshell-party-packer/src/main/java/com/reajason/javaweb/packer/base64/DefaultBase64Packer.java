package com.reajason.javaweb.packer.base64;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.PackerMeta;
import com.reajason.javaweb.packer.Packers;
import org.kohsuke.MetaInfServices;

/**
 * @author ReaJason
 * @since 2024/12/17
 */
@MetaInfServices(Packer.class)
@PackerMeta(name = Packers.DefaultBase64, parent = Packers.Base64, order = 110)
public class DefaultBase64Packer implements Packer {
    @Override
    public String pack(ClassPackerConfig config) {
        return config.getClassBytesBase64Str();
    }
}
