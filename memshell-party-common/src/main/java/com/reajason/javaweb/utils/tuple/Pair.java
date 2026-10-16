package com.reajason.javaweb.utils.tuple;

import java.io.Serializable;
import java.util.Objects;

/**
 * 二元组，语义与 {@code org.apache.commons.lang3.tuple.Pair} 对齐。
 * <p>
 * 项目原先通过 {@code commons-lang3} 传递依赖使用，为去掉该依赖，这里只保留仓库内实际用到的部分。
 * {@code getKey/getValue} 与 {@code getLeft/getRight} 指向同一对元素，两种命名在仓库中都有历史用法。
 *
 * @author ReaJason
 */
public class Pair<L, R> implements Serializable {

    private static final long serialVersionUID = 1L;

    private final L left;
    private final R right;

    protected Pair(L left, R right) {
        this.left = left;
        this.right = right;
    }

    public static <L, R> Pair<L, R> of(L left, R right) {
        return new Pair<>(left, right);
    }

    public L getLeft() {
        return left;
    }

    public R getRight() {
        return right;
    }

    public L getKey() {
        return left;
    }

    public R getValue() {
        return right;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Pair)) {
            return false;
        }
        Pair<?, ?> other = (Pair<?, ?>) obj;
        return Objects.equals(left, other.left) && Objects.equals(right, other.right);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(left) ^ Objects.hashCode(right);
    }

    @Override
    public String toString() {
        return "(" + left + "," + right + ")";
    }
}
