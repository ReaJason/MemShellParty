package org.apache.struts2.dispatcher.filter;

import com.reajason.javaweb.probe.payload.ServerProbe;

/**
 * 测试桩：ServerProbe 通过线程栈里的 Struts2 过滤器类名识别 Struts2 框架，
 * 借这个同名类把特征类名压进当前线程的调用栈
 *
 * @author ReaJason
 */
public class StrutsPrepareAndExecuteFilter {

    public static String detect() {
        return ServerProbe.exit(null);
    }

    /**
     * 同时把 SpringWebMvc 特征类压栈，验证多个框架前缀的拼接顺序
     */
    public static String detectWithSpringMvc() {
        return org.springframework.web.servlet.DispatcherServlet.detect();
    }
}
