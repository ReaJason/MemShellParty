FROM openjdk:8
WORKDIR /app

COPY build/libs/*.jar /app/app.jar

EXPOSE 8080

ENTRYPOINT java $JAVA_OPTS -jar app.jar