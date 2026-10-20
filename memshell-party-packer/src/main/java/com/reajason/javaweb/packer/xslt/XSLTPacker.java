package com.reajason.javaweb.packer.xslt;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.PackerMeta;
import com.reajason.javaweb.packer.Packers;
import org.kohsuke.MetaInfServices;

/**
 * @author ReaJason
 * @since 2026/8/30
 */
@MetaInfServices(Packer.class)
@PackerMeta(name = Packers.XSLT, order = 2100)
public class XSLTPacker implements Packer {

    /**
     * 直接选中分组名时沿用历史语义：输出第一个子打包器的结果。
     */
    @Override
    public String pack(ClassPackerConfig config) {
        return new XSLTScriptEnginePacker().pack(config);
    }
}
