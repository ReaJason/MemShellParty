package org.apache.coyote;

/**
 * Tomcat {@code org.apache.coyote.Request} 的生成期桩：Upgrade 模板（{@code accept(Request)}）只用到
 * note 读写。真实 Tomcat 里它是 final class，桩保持 class 以生成一致的 invokevirtual。
 *
 * @author ReaJason
 * @since 2026/10/13
 */
public final class Request {

    public Object getNote(int pos) {
        throw new UnsupportedOperationException();
    }

    public void setNote(int pos, Object note) {
        throw new UnsupportedOperationException();
    }
}
