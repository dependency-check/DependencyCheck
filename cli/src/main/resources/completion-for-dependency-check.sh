#/usr/bin/env bash

# To use completion for dependency-check you must run:
#
#         source completion-for-dependency-check.sh
#

_odc_completions()
{
    # Pointer to current completion word.
    local options="
            --advancedHelp
            --artifactoryApiToken
            --artifactoryBearerToken
            --artifactoryParallelAnalysis
            --artifactoryUseProxy
            --artifactoryUsername
            --bundleAudit
            --bundleAuditWorkingDirectory
        -c --connectiontimeout
            --connectionString
        -d --data
            --dbDriverName
            --dbDriverPath
            --dbPassword
            --dbUser
            --disableArchive
            --disableAssembly
            --disableAutoconf
            --disableBundleAudit
            --disableCentral
            --disableCentralCache
            --disableCmake
            --disableCocoapodsAnalyzer
            --disableCarthageAnalyzer
            --disableComposer
            --disableDart
            --disableFileName
            --disableGolangDep
            --disableGolangMod
            --disableHostedSuppressions
            --disableJar
            --disableMavenInstall
            --disableMixAudit
            --disableMSBuild
            --disableYarnAudit
            --disablePnpmAudit
            --disableNodeAudit
            --disableNodeAuditCache
            --disableNodeJS
            --disableNugetconf
            --disableNuspec
            --disableOpenSSL
            --disableOssIndex
            --disableOssIndexCache
            --ossIndexRemoteErrorWarnOnly
            --disableKnownExploited
            --kevURL <url>
            --disablePip
            --disablePipfile
            --disablePyDist
            --disablePyPkg
            --disableRetireJS
            --disableRubygems
            --disableSwiftPackageManagerAnalyzer
            --disableSwiftPackageResolvedAnalyzer
            --dotnet
            --enableArtifactory
            --enableExperimental
            --enableNexus
            --enableRetired
            --exclude <pattern>
        -f --format <format>
            --failOnCVSS <score>
            --go
        -h --help
            --hints
            --hostedSuppressionsForceUpdate
            --hostedSuppressionsValidForHours <hours>
            --hostedSuppressionsUrl <url>
            --hostedSuppressionsAuthHeader <authorization header>
            --junitFailOnCVSS <score>
        -l --log
        -n --noupdate
            --nexus <url>
            --nexusPass <password>
            --nexusUser <username>
            --nexusUsesProxy
            --nodeAuditSkipDevDependencies
            --nodePackageSkipDevDependencies
            --nonProxyHosts <list>
            --nvdApiKey <apiKey>
            --nvdDatafeed <url>
            --nvdUser <user>
            --nvdPassword <password>
            --nvdApiDelay <ms>
            --nvdValidForHours <hours>
        -o --out
            --ossIndexPassword <password>
            --ossIndexUsername <username>
        -P --propertyfile
            --prettyPrint
            --project <name>
            --proxypass <pass>
            --proxyport <port>
            --proxyserver <server>
            --proxyuser <user>
            --pnpm
            --purge
            --retirejsFilter <pattern>
            --retirejsFilterNonVulnerable
            --retireJsForceUpdate
            --retireJsUrl <url>
        -s --scan
            --suppression
            --symLink <depth>
            --updateonly
        -v --version
            --yarn
            --zipExtensions <extensions>
    "


    # Array variable storing the possible completions.
    COMPREPLY=()
    local cur=${COMP_WORDS[COMP_CWORD]}
    local prev="${COMP_WORDS[COMP_CWORD-1]}"


    case "${prev}" in
        -s|--scan|-o|--out|-d|--data|--bundleAudit|--bundleAuditWorkingDirectory|--dbDriverPath|--dotnet|--go|-P|--propertyfile|--suppression|--hint|-l|--log|--yarn)
            COMPREPLY=( $(compgen -f -o default -- ${cur}) )
            return 0
            ;;
        --artifactoryParallelAnalysis|--artifactoryUseProxy|--nexusUsesProxy)
            COMPREPLY=( $(compgen -W "true false" -- ${cur}) )
            return 0
            ;;
        -f|--format)
            COMPREPLY=( $(compgen -W "HTML XML CSV JSON JUNIT SARIF ALL" ${cur}) )
            return 0
            ;;
    esac
    if [[ "$cur" == -* ]] ; then
        COMPREPLY=( $(compgen -W "$options" -- "$cur") )
        return 0
    fi
  return 0
}

complete -F _odc_completions dependency-check.sh
