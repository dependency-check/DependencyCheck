package org.owasp.dependencycheck;

import java.io.File;
import java.io.IOException;
import java.lang.instrument.Instrumentation;
import java.util.jar.JarFile;

/**
 * Java agent for loading plugin JARs from a specified directory into the system classpath
 * before the main application starts. This allows additional plugins to be available at runtime
 * by appending their JAR files to the system class loader search path; while allowing use of an
 * executable jar with deterministic classpath ordering.
 * <p>
 * To use, specify this class as a Java agent and provide the plugins directory as the -javaagent argument
 * </p>
 */
public class PluginLoader {
    /**
     * Java agent entry point. Loads all JAR files from the specified plugins directory
     * and appends them to the system class loader search path.
     *
     * @param agentArg the path to the plugins directory containing JAR files to load, e.g `-javaagent:cli.jar=/usr/share/dependency-check/plugins`
     * @param inst     the instrumentation instance provided by the JVM
     */
    public static void premain(String agentArg, Instrumentation inst) {
        File pluginsDir = new File(agentArg);
        if (pluginsDir.isDirectory()) {
            File[] files = pluginsDir.listFiles((dir, name) -> name.endsWith(".jar"));
            for (File file : files == null ? new File[0] : files) {
                try (JarFile jar = new JarFile(file)) {
                    inst.appendToSystemClassLoaderSearch(jar);
                } catch (IOException e) {
                    System.err.printf("[WARN] Failed to read plugin jar file at %s. Jar will not be available on classpath: %s%n", file, e);
                    e.printStackTrace(System.err);
                }
            }
        }
    }
}