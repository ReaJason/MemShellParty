package com.reajason.javaweb.packer.translet;

import com.reajason.javaweb.asm.ClassSuperClassUtils;
import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.PackerMeta;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.utils.Base64Utils;
import lombok.SneakyThrows;
import org.kohsuke.MetaInfServices;

/**
 * @author ReaJason
 * @since 2025/11/19
 */
@MetaInfServices(Packer.class)
@PackerMeta(name = Packers.JDKAbstractTransletPacker, parent = Packers.AbstractTranslet, order = 510)
public class JDKAbstractTransletPacker implements Packer {
    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        String superClassName = "com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet";
        byte[] bytes = Base64Utils.decodeBase64(config.getClassBytesBase64Str());
        byte[] newBytes = ClassSuperClassUtils.addSuperClass(bytes, superClassName);
        return Base64Utils.encodeBase64String(newBytes);
    }
}
