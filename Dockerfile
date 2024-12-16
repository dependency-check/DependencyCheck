FROM golang:1.23.4-alpine AS go

FROM azul/zulu-openjdk-alpine:21 AS jlink

RUN "$JAVA_HOME/bin/jlink" --compress=2 --module-path /opt/java/openjdk/jmods --add-modules java.base,java.compiler,java.datatransfer,jdk.crypto.ec,java.desktop,java.instrument,java.logging,java.management,java.naming,java.rmi,java.scripting,java.security.sasl,java.sql,java.transaction.xa,java.xml,jdk.unsupported --output /jlinked

FROM mcr.microsoft.com/dotnet/runtime:8.0-alpine3.18

ARG VERSION
ARG POSTGRES_DRIVER_VERSION=42.2.19
ARG MYSQL_DRIVER_VERSION=8.0.23
ARG UID=1000
ARG GID=1000

ENV user=dependencycheck
ENV JAVA_HOME=/opt/jdk
ENV JAVA_OPTS="-Danalyzer.assembly.dotnet.path=/usr/bin/dotnet -Danalyzer.bundle.audit.path=/usr/bin/bundle-audit -Danalyzer.golang.path=/usr/local/go/bin/go"

COPY --from=jlink /jlinked /opt/jdk/
COPY --from=go /usr/local/go/ /usr/local/go/

ADD cli/target/dependency-check-${VERSION}-release.zip /

RUN apk update                                                                                       && \
    apk add --no-cache --virtual .build-deps curl tar                                                && \
    apk add --no-cache git ruby ruby-rdoc npm                                                        && \
    gem install bundle-audit                                                                         && \
    bundle audit update                                                                              && \
    mkdir /opt/yarn                                                                                  && \
    curl -Ls https://yarnpkg.com/latest.tar.gz | tar -xz --strip-components=1 --directory /opt/yarn  && \
    ln -s /opt/yarn/bin/yarn /usr/bin/yarn                                                           && \
    npm install -g pnpm                                                                              && \
    unzip dependency-check-${VERSION}-release.zip -d /usr/share/                                     && \
    rm dependency-check-${VERSION}-release.zip                                                       && \
    cd /usr/share/dependency-check/plugins                                                           && \
    curl -Os "https://jdbc.postgresql.org/download/postgresql-${POSTGRES_DRIVER_VERSION}.jar"        && \
    curl -Ls "https://dev.mysql.com/get/Downloads/Connector-J/mysql-connector-java-${MYSQL_DRIVER_VERSION}.tar.gz" \
        | tar -xz --directory "/usr/share/dependency-check/plugins" --strip-components=1 --no-same-owner \
            "mysql-connector-java-${MYSQL_DRIVER_VERSION}/mysql-connector-java-${MYSQL_DRIVER_VERSION}.jar" && \
    addgroup -S -g ${GID} ${user} && adduser -S -D -u ${UID} -G ${user} ${user}                      && \
    mkdir /usr/share/dependency-check/data                                                           && \
    chown -R ${user}:0 /usr/share/dependency-check                                                   && \
    chmod -R g=u /usr/share/dependency-check                                                         && \
    mkdir /report                                                                                    && \
    chown -R ${user}:0 /report                                                                       && \
    chmod -R g=u /report                                                                             && \
    apk del .build-deps

### remove any suid sgid - we don't need them
RUN find / -perm +6000 -type f -exec chmod a-s {} \;
USER ${UID}

VOLUME ["/src", "/report"]

WORKDIR /src

CMD ["--help"]
ENTRYPOINT ["/usr/share/dependency-check/bin/dependency-check.sh"]
