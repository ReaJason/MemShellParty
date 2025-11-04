FROM eclipse-temurin:8u472-b08-jdk
WORKDIR /app

COPY build/libs/vul-springboot1.jar /app/app.jar

EXPOSE 8080

ENTRYPOINT java $JAVA_OPTS -jar app.jar