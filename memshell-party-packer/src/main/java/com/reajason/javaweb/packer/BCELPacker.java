package com.reajason.javaweb.packer;

import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.PackerMeta;
import lombok.SneakyThrows;
import org.apache.bcel.classfile.Utility;
import org.kohsuke.MetaInfServices;

/**
 * @author ReaJason
 * @since 2024/12/19
 */
@MetaInfServices(Packer.class)
@PackerMeta(name = Packers.BCEL, requiresClasses = {"org.apache.bcel.classfile.Utility"}, order = 400)
public class BCELPacker implements Packer {
    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        return "$$BCEL$$" + Utility.encode(config.getClassBytes(), true);
    }
}
