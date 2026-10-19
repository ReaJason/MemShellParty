package org.springframework.web.servlet;

import com.reajason.javaweb.probe.payload.ServerProbe;

/**
 * 测试桩：ServerProbe 通过线程栈里的 DispatcherServlet 类名识别 SpringWebMvc 框架，
 * 借这个同名类把特征类名压进当前线程的调用栈
 *
 * @author ReaJason
 */
public class DispatcherServlet {

    public static String detect() {
        return ServerProbe.exit(null);
    }
}
