FROM --platform=$BUILDPLATFORM  buildpack-deps:bullseye-scm AS source

WORKDIR /usr/src

RUN git clone --depth 1 https://github.com/ReaJason/MemShellParty.git . && \
    rm -rf vul integration-test tools

# https://hub.docker.com/r/oven/bun
FROM --platform=$BUILDPLATFORM oven/bun:1.3.2 AS frontend

ARG ROUTE_ROOT_PATH="/"
ARG CONTEXT_PATH=""

WORKDIR /usr/src/web

ENV VITE_APP_API_URL=${CONTEXT_PATH} \
    VITE_APP_BASE_PATH=${ROUTE_ROOT_PATH}

COPY --from=source /usr/src/web/package.json /usr/src/web/bun.lockb /usr/src/web/

RUN bun install --frozen-lockfile

COPY --from=source /usr/src/web /usr/src/web

RUN bun run build

# https://hub.docker.com/_/eclipse-temurin/tags?name=17.
FROM --platform=$BUILDPLATFORM  eclipse-temurin:17.0.15_6-jdk-noble AS backend

WORKDIR /usr/src

COPY --from=source /usr/src /usr/src

COPY --from=frontend /usr/src/boot/src/main/resources /usr/src/boot/src/main/resources

RUN ./gradlew :boot:bootjar -x test

FROM eclipse-temurin:17.0.15_6-jre-noble

LABEL authors="ReaJason<reajason1225@gmail.com>"

WORKDIR /app

RUN groupadd -r spring && \
    useradd -r -g spring spring

COPY --from=backend --chown=spring:spring /usr/src/boot/build/libs/*.jar app.jar

USER spring:spring

ENV INTERNAL_JAVA_OPTS="\
    -Djava.security.egd=file:/dev/./urandom -Dfastison.parser.safeMode=true \
    --add-opens=java.base/java.util=ALL-UNNAMED \
    --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
    --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED"

EXPOSE 8080

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS $INTERNAL_JAVA_OPTS -jar app.jar $BOOT_OPTS"]