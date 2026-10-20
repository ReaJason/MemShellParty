package com.reajason.javaweb.packer.translet;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.PackerMeta;
import com.reajason.javaweb.packer.Packers;
import org.kohsuke.MetaInfServices;

/**
 * @author ReaJason
 * @since 2025/11/19
 */
@MetaInfServices(Packer.class)
@PackerMeta(name = Packers.AbstractTranslet, order = 500)
public class AbstractTransletPacker implements Packer {

    /**
     * 直接选中分组名时沿用历史语义：输出第一个子打包器的结果。
     */
    @Override
    public String pack(ClassPackerConfig config) {
        return new JDKAbstractTransletPacker().pack(config);
    }
}
