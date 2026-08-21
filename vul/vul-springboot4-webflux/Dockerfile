FROM eclipse-temurin:21.0.11_10-jdk
WORKDIR /app

COPY build/libs/vul-springboot4-webflux.jar /app/app.jar

EXPOSE 8080

ENTRYPOINT java $JAVA_OPTS -jar app.jar
