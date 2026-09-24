package com.xxl.job.core.biz.model;

import java.io.Serializable;

/**
 * 精简版 ReturnT，仅用于在测试中编译 GLUE 源码
 */
public class ReturnT<T> implements Serializable {
    public static final ReturnT<String> SUCCESS = new ReturnT<>();
}
