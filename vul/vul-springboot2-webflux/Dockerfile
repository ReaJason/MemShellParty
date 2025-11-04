FROM eclipse-temurin:8u472-b08-jdk
WORKDIR /app

COPY build/libs/vul-springboot2-webflux.jar /app/vul-springboot2-webflux.jar

EXPOSE 8080

ENTRYPOINT java $JAVA_OPTS -jar vul-springboot2-webflux.jar