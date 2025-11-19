package com.reajason.javaweb.packer.translet;

import com.reajason.javaweb.asm.ClassSuperClassUtils;
import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import lombok.SneakyThrows;
import org.apache.commons.codec.binary.Base64;

/**
 * @author ReaJason
 * @since 2025/11/19
 */
public class OracleAbstractTransletPacker implements Packer {
    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        String superClassName = "com.oracle.wls.shaded.org.apache.xalan.xsltc.runtime.AbstractTranslet";
        byte[] bytes = Base64.decodeBase64(config.getClassBytesBase64Str());
        byte[] newBytes = ClassSuperClassUtils.addSuperClass(bytes, superClassName);
        return Base64.encodeBase64String(newBytes);
    }
}
