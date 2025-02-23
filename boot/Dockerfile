FROM eclipse-temurin:17-jre

ARG VERSION=1.0.0

ENV VERSION=$VERSION

LABEL authors="ReaJason<reajason1225@gmail.com>"

WORKDIR /app
COPY build/libs/boot-${VERSION}.jar app.jar

ENV INTERNAL_JAVA_OPTS="\
                    --add-opens=java.base/java.util=ALL-UNNAMED \
                    --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
                    --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED"

EXPOSE 8080

ENTRYPOINT java $JAVA_OPTS $INTERNAL_JAVA_OPTS -jar app.jar $BOOT_OPTS
