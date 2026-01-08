package com.reajason.javaweb.packer.deserialize.java;

import com.reajason.javaweb.packer.ClassPackerConfig;
import net.bytebuddy.ByteBuddy;
import org.junit.jupiter.api.Test;

/**
 * @author ReaJason
 * @since 2026/1/4
 */
class CommonsBeanutils19PackerTest {

    @Test
    void test(){
        byte[] bytes = new ByteBuddy().redefine(EvilClass.class).name("hello.world").make().getBytes();
        ClassPackerConfig classPackerConfig = new ClassPackerConfig();
        classPackerConfig.setClassBytes(bytes);
        System.out.println(new CommonsBeanutils19Packer().pack(classPackerConfig));
    }

}