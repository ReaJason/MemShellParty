### 目录结构

- bom: 依赖版本管理，不用写到处写版本号就是舒服
- boot：使用 SpringBoot 为 UI 提供生成服务
- common：bytebuddy 等工具类存放
- generator：内存马生成核心
- deserialize：反序列化相关 gadget
- integration-test：集成测试用例
- memshell：内存功能类以及注入器（为保证兼容性够高，所以单独弄出来）
- memshell-java8：Spring 相关的存在 lambda 表达式所以单独弄出来
- tools/behinder：冰蝎简易连接器
- tools/godzilla：哥斯拉简易连接器
- tools/suo5：Suo5 简易连接器
- web：使用 react 开发的 Web UI
- vul/vul-webapp：简易的 javax.servlet 靶场
- vul/vul-webapp-expression：简易的表达式注入、SSTI 注入相关靶场
- vul/vul-webapp-jakarta：简易的 jakarta.servlet 靶场
- vul/springboot*: springboot 相关靶场

### 编译

整个项目需要使用 JDK17 进行编译运行，由于集成测试用例过多，请不要在本地执行，使用构建命令时指定目标模块

```bash
# 编译 generator 模块
./gradlew :generator:build

# 运行集成测试用例，谨慎运行，用例太多了
./gradlew :integration-test:test --info

# 仅运行 tomcat 下的集成测试用例
./gradlew :integration-test:test --tests '*.tomcat.*'
# 仅运行 jetty 下的集成测试用例
./gradlew :integration-test:test --tests '*.jetty.*'

# 构建 war 包
./gradlew :vul:vul-webapp:war
./gradlew :vul:vul-webapp-jakarta:war
./gradlew :vul:vul-webapp-expression:war
```

### SpringBoot + React 前端编译

UI 采用的 React SPA + SpringBoot，构建时需要先将 React 前端项目编译之后移动到 SpringBoot 中的 static 和 templates 中。

构建和打包流程参考 CI。

开发流程：

1. 先启动后端服务，`./gradlew :boot:bootRun`
2. 接着启动前端服务，`cd web && bun install && bun run dev`

打包流程：

1. 先打包前端项目，`bun run build`
2. 再打包后端项目，`./gradlew :boot:bootJar`

### Contribute Code

> 参考 GitHub Docs， https://docs.github.com/en/get-started/exploring-projects-on-github/contributing-to-a-project

1. fork 当前项目
2. git clone 自己 fork 后的项目
3. 创建一个新的分支来编写代码和添加测试用例
4. git push 你的代码
5. 创建 pull request

<hr>

**for free to make a pull request or write a issue 🎉**