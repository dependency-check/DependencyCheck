FROM golang:1.26.2-alpine AS go

FROM azul/zulu-openjdk-alpine:25 AS jlink

RUN "$JAVA_HOME/bin/jlink" --compress=zip-6 --module-path /opt/java/openjdk/jmods --add-modules java.base,java.compiler,java.datatransfer,jdk.crypto.ec,java.desktop,java.instrument,java.logging,java.management,java.naming,java.rmi,java.scripting,java.security.sasl,java.sql,java.transaction.xa,java.xml,jdk.unsupported,jdk.net --output /jlinked

FROM mcr.microsoft.com/dotnet/runtime:8.0-alpine

ARG VERSION
ARG POSTGRES_DRIVER_VERSION
ARG MYSQL_DRIVER_VERSION
ARG MAVEN_REPOSITORY_URL="https://repo1.maven.org/maven2"
ARG UID=1000
ARG GID=1000

ENV user=dependencycheck
ENV JAVA_HOME=/opt/jdk
ENV JAVA_OPTS="-Danalyzer.assembly.dotnet.path=/usr/bin/dotnet -Danalyzer.bundle.audit.path=/usr/bin/bundle-audit -Danalyzer.golang.path=/usr/local/go/bin/go"
ENV ODC_NAME=dependency-check-docker
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=false

COPY --from=jlink /jlinked /opt/jdk/
COPY --from=go /usr/local/go/ /usr/local/go/

ADD cli/target/dependency-check-${VERSION}-release.zip /

RUN apk upgrade --no-cache                                                                           && \
    apk add --no-cache --virtual .build-deps curl                                                    && \
    apk add --no-cache git ruby npm                                                                  && \
    gem install --no-document bundler-audit                                                          && \
    npm install --global --ignore-scripts corepack                                                   && \
    unzip dependency-check-${VERSION}-release.zip -d /usr/share/                                     && \
    rm dependency-check-${VERSION}-release.zip                                                       && \
    cd /usr/share/dependency-check/plugins                                                           && \
    curl -fSLO "${MAVEN_REPOSITORY_URL}/org/postgresql/postgresql/${POSTGRES_DRIVER_VERSION}/postgresql-${POSTGRES_DRIVER_VERSION}.jar"    && \
    curl -fSLO "${MAVEN_REPOSITORY_URL}/com/mysql/mysql-connector-j/${MYSQL_DRIVER_VERSION}/mysql-connector-j-${MYSQL_DRIVER_VERSION}.jar" && \
    addgroup -S -g ${GID} ${user} && adduser -S -D -u ${UID} -G ${user} ${user}                      && \
    mkdir /usr/share/dependency-check/data                                                           && \
    chown -R ${user}:0 /usr/share/dependency-check                                                   && \
    chmod -R g=u /usr/share/dependency-check                                                         && \
    mkdir /report                                                                                    && \
    chown -R ${user}:0 /report                                                                       && \
    chmod -R g=u /report                                                                             && \
    apk del .build-deps                                                                              && \
    rm -rf /tmp/* /root/.cache /root/.npm

### remove any suid sgid - we don't need them
RUN find / -path /proc -prune -perm +6000 -type f -exec chmod a-s {} \;
USER ${UID}

### Cache pieces needed for the specific run user
RUN bundle audit update                                                                              && \
    corepack prepare pnpm@latest yarn@latest yarn@1 --activate                                       && \
    printf "enableTelemetry: false\nenableScripts: false\n" >> ${HOME}/.yarnrc.yml                   && \
    rm -rf /tmp/*

VOLUME ["/src", "/report"]

WORKDIR /src

CMD ["--help"]
ENTRYPOINT ["/usr/share/dependency-check/bin/dependency-check.sh"]
