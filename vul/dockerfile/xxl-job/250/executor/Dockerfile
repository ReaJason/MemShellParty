FROM maven:3.9.9-eclipse-temurin-17 AS builder

WORKDIR /usr/src

RUN set -ex \
    && git clone --depth 1 -b 2.5.0 https://github.com/xuxueli/xxl-job.git . \
    && ls \
    && cd xxl-job-executor-samples/xxl-job-executor-sample-springboot \
    && sed -i 's|xxl\.job\.admin\.addresses=.*|xxl.job.admin.addresses=http://admin:8080/xxl-job-admin|g' src/main/resources/application.properties \
    && sed -i 's|xxl\.job\.executor\.logpath=.*|xxl.job.executor.logpath=/var/log/xxl-job|g' src/main/resources/application.properties \
    && mvn clean package -DskipTests

FROM eclipse-temurin:17-jdk

RUN set -ex \
    && apt-get update \
    && apt-get install -y --no-install-recommends wait-for-it \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/xxl-job-executor-samples/xxl-job-executor-sample-springboot/target/xxl-job-executor-sample-springboot-2.5.0.jar /usr/src/xxl-job-executor-sample-springboot-2.5.0.jar
COPY docker-entrypoint.sh /docker-entrypoint.sh

WORKDIR /usr/src
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["java", "-jar", "/usr/src/xxl-job-executor-sample-springboot-2.5.0.jar"]