FROM maven:3.9.9-eclipse-temurin-8 AS builder

RUN set -ex \
    && cd /usr/src \
    && git clone --depth 1 -b v2.2.0 https://github.com/xuxueli/xxl-job.git . \
    && cd xxl-job-admin \
    && sed -i 's/spring\.datasource\.password=.*/spring.datasource.password=root/g' src/main/resources/application.properties \
    && sed -i 's|mysql://127\.0\.0\.1:3306|mysql://db:3306|g' src/main/resources/application.properties \
    && mvn clean package -DskipTests

FROM eclipse-temurin:8-jdk

RUN set -ex \
    && apt-get update \
    && apt-get install -y --no-install-recommends wait-for-it default-mysql-client \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/xxl-job-admin/target/xxl-job-admin-2.2.0.jar /usr/src/xxl-job-admin-2.2.0.jar
COPY docker-entrypoint.sh /docker-entrypoint.sh
COPY --from=builder /usr/src/doc/db/tables_xxl_job.sql /usr/src/tables_xxl_job.sql

WORKDIR /usr/src
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["java", "-jar", "/usr/src/xxl-job-admin-2.2.0.jar"]