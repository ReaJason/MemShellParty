package com.reajason.javaweb.packer;

import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.PackerMeta;
import lombok.SneakyThrows;
import org.kohsuke.MetaInfServices;

import java.math.BigInteger;

/**
 * @author Wans
 * @since 2025/08/26
 */
@MetaInfServices(Packer.class)
@PackerMeta(name = Packers.BigInteger, order = 300)
public class BigIntegerPacker implements Packer {
    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        return new BigInteger(config.getClassBytes()).toString(Character.MAX_RADIX);
    }
}
