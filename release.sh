#!/usr/bin/env bash

DIR=$(dirname "$0")
MAVEN_REPOSITORY_NAME='ns-releases'
MAVEN_REPOSITORY_URL='artifactregistry://europe-west2-maven.pkg.dev/newsome-solutions/libs-release-local'
MAVEN_SETTINGS_XML='<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0http://maven.apache.org/xsd/settings-1.0.0.xsd"><localRepository /><interactiveMode /><usePluginRegistry /><offline /><pluginGroups /><servers /><mirrors /><proxies /><profiles><profile><id>ns-build</id><properties><version.extension.artifactregistry-maven-wagon>2.2.0</version.extension.artifactregistry-maven-wagon></properties><repositories><repository><id>artifact-registry</id><url>artifactregistry://europe-west2-maven.pkg.dev/newsome-solutions/libs-release-local</url><releases><enabled>true</enabled></releases><snapshots><enabled>false</enabled></snapshots></repository></repositories></profile></profiles><activeProfiles><activeProfile>ns-build</activeProfile></activeProfiles></settings>'

cd $DIR
set -euo pipefail

# 1. Ensure working directory is clean
#if [[ -n $(git status --porcelain) ]]; then
#  echo "Error: Working directory is not clean. Commit or stash changes first."
#  exit 1
#fi
#
#mkdir -p $DIR/.mvn
#mkdir -p $DIR/target
#echo "<extensions xmlns=\"http://maven.apache.org/EXTENSIONS/1.0.0\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"http://maven.apache.org/EXTENSIONS/1.0.0 http://maven.apache.org/xsd/core-extensions-1.0.0.xsd\"><extension><groupId>com.google.cloud.artifactregistry</groupId><artifactId>artifactregistry-maven-wagon</artifactId><version>2.2.0</version></extension></extensions>" > $DIR/.mvn/extensions.xml
#echo "$MAVEN_SETTINGS_XML" > $DIR/target/maven-settings.xml
#
## 2. Extract current version from root POM
#CURRENT_VERSION=$(mvn help:evaluate -Dexpression=project.version -q -DforceStdout)
#echo "Current Version: ${CURRENT_VERSION}"
#
#if [[ "${CURRENT_VERSION}" != *"-SNAPSHOT" ]]; then
#  echo "Error: Current version is not a SNAPSHOT version."
#  exit 1
#fi
#
## 3. Calculate Release Version (removes -SNAPSHOT)
#RELEASE_VERSION="${CURRENT_VERSION%-SNAPSHOT}"
#read -p "Enter release version [${RELEASE_VERSION}]: " INPUT_RELEASE
#RELEASE_VERSION="${INPUT_RELEASE:-$RELEASE_VERSION}"
#
## 4. Calculate Next SNAPSHOT Version
## Bumps trailing digit (e.g., 13.0.1-1.0 -> 13.0.1-1.1-SNAPSHOT)
#BASE_NUM=$(echo "${RELEASE_VERSION}" | grep -oE '[0-9]+$')
#NEXT_NUM=$((BASE_NUM + 1))
#PREFIX="${RELEASE_VERSION%"$BASE_NUM"}"
#NEXT_SNAPSHOT="${PREFIX}${NEXT_NUM}-SNAPSHOT"
#
#read -p "Enter next SNAPSHOT version [${NEXT_SNAPSHOT}]: " INPUT_NEXT
#NEXT_SNAPSHOT="${INPUT_NEXT:-$NEXT_SNAPSHOT}"
#
#echo "========================================="
#echo " Releasing:    ${RELEASE_VERSION}"
#echo " Next Version: ${NEXT_SNAPSHOT}"
#echo "========================================="
#
## 5. Set Release Version across all submodules
#mvn versions:set -DnewVersion="${RELEASE_VERSION}" -DgenerateBackupPoms=false -s $DIR/target/maven-settings.xml
#
## 6. Build and Deploy to GCP
#echo "Deploying to GCP Artifact Registry..."
#mvn -B deploy -DskipTests \
#  -DaltDeploymentRepository=${MAVEN_REPOSITORY_NAME}::default::${MAVEN_REPOSITORY_URL} \
#  -s $DIR/target/maven-settings.xml
#
## 7. Git Tag and Commit Release
#git commit -am "chore(release): prepare release v${RELEASE_VERSION}"
RELEASE_VERSION="13.0.1-0.1"
NEXT_SNAPSHOT="13.0.1-0.2-SNAPSHOT"
git tag -a "v${RELEASE_VERSION}" -m "Release v${RELEASE_VERSION}"

# 8. Bump to Next SNAPSHOT Version
mvn versions:set -DnewVersion="${NEXT_SNAPSHOT}" -DgenerateBackupPoms=false
git commit -am "chore(release): prepare for next development iteration ${NEXT_SNAPSHOT}"

echo "Release v${RELEASE_VERSION} completed successfully!"
echo "Run 'git push origin main --tags' to publish your changes."

rm -rf $DIR/.mvn/extensions.xml
