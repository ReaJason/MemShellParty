package com.reajason.javaweb.packer.deserialize.java;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.PackerMeta;
import com.reajason.javaweb.packer.Packers;
import org.kohsuke.MetaInfServices;

/**
 * @author ReaJason
 * @since 2024/12/10
 */
@MetaInfServices(Packer.class)
@PackerMeta(name = Packers.JavaDeserialize, order = 2200)
public class JavaDeserializePacker implements Packer {

    /**
     * 直接选中分组名时沿用历史语义：输出第一个子打包器的结果。
     */
    @Override
    public String pack(ClassPackerConfig config) {
        return new CommonsBeanutils19Packer().pack(config);
    }

}
