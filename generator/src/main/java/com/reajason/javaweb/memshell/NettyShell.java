package com.reajason.javaweb.memshell;

import org.apache.commons.lang3.tuple.Pair;

import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/12/26
 */
public class NettyShell extends AbstractShell{
    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getBehinderShellMap() {
        return super.getBehinderShellMap();
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        return super.getCommandShellMap();
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        return super.getGodzillaShellMap();
    }
}
