### 目录结构

- boot：使用 SpringBoot 为 UI 提供生成服务
- web：使用 react 开发的 Web UI
- deserialize：反序列化相关 gadget
- generator：内存马生成核心
- integration-test：集成测试用例
- vul-webapp：简易的 javax.servlet 靶场
- vul-webapp-expression：简易的表达式注入、SSTI 注入相关靶场
- vul-webapp-jakarta：简易的 jakarta.servlet 靶场

### 编译

整个项目需要使用 JDK17 进行编译运行，由于集成测试用例过多，请不要在本地执行构建命令时指定目标模块

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
./gradlew :vul-webapp:war
./gradlew :vul-webapp-jakarta:war
./gradlew :vul-webapp-expression:war
```

### Contribute Something

> 你对此项目的任何反馈以及 issue 交流都是对当前项目的贡献

1. 你有高超的 Docker 环境构建技术，可以添加 CVE 相关的集成测试用例。
2. 你有高超的内存马编写技术，可以尝试添加一个内存马试试。
3. 你有丰富的实战经验，可以尝试写写 issue 来提提建议。

### Contribute Code

> 参考 GitHub Docs， https://docs.github.com/en/get-started/exploring-projects-on-github/contributing-to-a-project

1. fork 当前项目
2. git clone 自己 fork 后的项目
3. 创建一个新的分支来编写代码和添加测试用例
4. git push 你的代码
5. 创建 pull request

<hr>

**for free to make a pull request or write a issue 🎉**