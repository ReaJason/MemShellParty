import java.lang.instrument.Instrumentation;

/**
 * @author ReaJason
 * @since 2025/5/22
 */
public class Agent {
    public static void premain(String args, Instrumentation inst) {
        System.out.println("hello premain");
    }

    public static void agentmain(String args, Instrumentation inst) {
        System.out.println("hello agentmain");
    }
}
