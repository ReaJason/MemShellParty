FROM eclipse-temurin:17.0.17_10-jre-noble

LABEL authors="ReaJason<reajason1225@gmail.com>"

WORKDIR /app

RUN groupadd -r spring && \
    useradd -r -g spring spring

COPY --chown=spring:spring build/libs/*.jar app.jar

USER spring:spring

ENV INTERNAL_JAVA_OPTS="\
    -Djava.security.egd=file:/dev/./urandom -Dfastison.parser.safeMode=true \
    --add-opens=java.base/java.util=ALL-UNNAMED \
    --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
    --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED"

EXPOSE 8080

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS $INTERNAL_JAVA_OPTS -jar app.jar $BOOT_OPTS"]