package com.reajason.javaweb.packer.jsp;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.PackerMeta;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.packer.Util;
import lombok.SneakyThrows;
import org.kohsuke.MetaInfServices;

/**
 * @author ReaJason
 * @since 2024/11/26
 */
@MetaInfServices(Packer.class)
@PackerMeta(name = Packers.DefineClassJSPUnicode, parent = Packers.JSP, order = 240)
public class DefineClassJspUnicodePacker implements Packer {

    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        return JspUnicoder.encode(new DefineClassJspPacker().pack(config), true);
    }
}
