FROM eclipse-temurin:17.0.17_10-jdk
WORKDIR /app

COPY build/libs/vul-springboot3-webflux.jar /app/app.jar

EXPOSE 8080

ENTRYPOINT java $JAVA_OPTS -jar app.jar