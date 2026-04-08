import java.util.List;

/**
 * @author ReaJason
 * @since 2025/5/16
 */
public class Main {
    /**
     * java -jar attach.jar — 列出所有 Java 进程
     * java -jar attach.jar <pid> — 注入指定进程
     * java -jar attach.jar all — 注入所有 Java 进程（自动跳过自身，单个失败不影响其他进程）
     */
    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            List<Attacher.JavaProcessDescriptor> processes = Attacher.listJavaProcesses();
            if (processes.isEmpty()) {
                System.out.println("No Java processes found.");
            } else {
                for (Attacher.JavaProcessDescriptor process : processes) {
                    System.out.println(process);
                }
            }
        } else if ("all".equalsIgnoreCase(args[0])) {
            List<Attacher.JavaProcessDescriptor> processes = Attacher.listJavaProcesses();
            String currentPid = Attacher.ProcessProvider.ForCurrentVm.INSTANCE.resolve();
            if (processes.isEmpty()) {
                System.out.println("No Java processes found.");
            } else {
                for (Attacher.JavaProcessDescriptor process : processes) {
                    if (process.getPid().equals(currentPid)) {
                        continue;
                    }
                    try {
                        System.out.println("Attaching to " + process + " ...");
                        Attacher.attach(process.getPid());
                        System.out.println("  -> Success");
                    } catch (Exception e) {
                        System.out.println("  -> Failed: " + e.getMessage());
                    }
                }
            }
        } else {
            Attacher.attach(args[0]);
        }
    }
}
