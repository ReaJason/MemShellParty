package com.reajason.javaweb.packer.jsp;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;

/**
 * @author ReaJason
 * @since 2024/11/26
 */
public class JspPacker implements Packer<JspCustomPackerConfig> {
    @Override
    public String pack(ClassPackerConfig<JspCustomPackerConfig> classPackerConfig) {
        return Packers.ClassLoaderJSP.getInstance().pack(classPackerConfig);
    }
}
