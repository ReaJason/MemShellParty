package com.reajason.javaweb.packer.testfixture;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.PackerMeta;

/**
 * 第三方 packer 夹具：不注册在 packer 模块里，只通过测试资源目录的
 * {@code META-INF/services/com.reajason.javaweb.packer.Packer} 暴露。
 *
 * @author ReaJason
 */
@PackerMeta(name = "ThirdPartyFixture", order = 9000)
public class ThirdPartyPacker implements Packer {

    @Override
    public String pack(ClassPackerConfig config) {
        return "third-party:" + config.getClassName();
    }
}
