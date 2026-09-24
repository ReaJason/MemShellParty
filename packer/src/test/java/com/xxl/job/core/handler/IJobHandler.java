package com.xxl.job.core.handler;

import com.xxl.job.core.biz.model.ReturnT;

/**
 * 精简版 IJobHandler，仅用于在测试中编译 GLUE 源码
 */
public abstract class IJobHandler {
    public abstract ReturnT<String> execute(String param) throws Exception;
}
