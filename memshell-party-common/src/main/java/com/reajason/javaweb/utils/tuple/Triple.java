package com.reajason.javaweb.utils.tuple;

import java.io.Serializable;
import java.util.Objects;

/**
 * 三元组，语义与 {@code org.apache.commons.lang3.tuple.Triple} 对齐。
 * <p>
 * 项目原先通过 {@code commons-lang3} 传递依赖使用，为去掉该依赖，这里只保留仓库内实际用到的部分。
 *
 * @author ReaJason
 */
public class Triple<L, M, R> implements Serializable {

    private static final long serialVersionUID = 1L;

    private final L left;
    private final M middle;
    private final R right;

    protected Triple(L left, M middle, R right) {
        this.left = left;
        this.middle = middle;
        this.right = right;
    }

    public static <L, M, R> Triple<L, M, R> of(L left, M middle, R right) {
        return new Triple<>(left, middle, right);
    }

    public L getLeft() {
        return left;
    }

    public M getMiddle() {
        return middle;
    }

    public R getRight() {
        return right;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Triple)) {
            return false;
        }
        Triple<?, ?, ?> other = (Triple<?, ?, ?>) obj;
        return Objects.equals(left, other.left)
                && Objects.equals(middle, other.middle)
                && Objects.equals(right, other.right);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(left) ^ Objects.hashCode(middle) ^ Objects.hashCode(right);
    }

    @Override
    public String toString() {
        return "(" + left + "," + middle + "," + right + ")";
    }
}
