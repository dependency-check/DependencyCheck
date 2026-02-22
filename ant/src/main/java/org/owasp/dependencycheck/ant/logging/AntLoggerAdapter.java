/*
 * This file is part of dependency-check-ant.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2015 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.ant.logging;

import java.util.Objects;
import org.apache.tools.ant.Project;
import org.apache.tools.ant.Task;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.helpers.FormattingTuple;
import org.slf4j.helpers.MessageFormatter;

/**
 * An instance of {@link org.slf4j.Logger} which simply calls the log method on
 * the current Ant task obtained from {@link AntTaskHolder}.
 *
 * @author colezlaw
 */
public class AntLoggerAdapter implements Logger {


    /**
     * The logger name.
     */
    private final String name;

    /**
     * Constructor.
     *
     * @param name the logger name
     */
    public AntLoggerAdapter(String name) {
        this.name = Objects.requireNonNull(name, "Logger name cannot be null");
    }

    @Override
    public String getName() {
        return name;
    }

    private Task task() {
        return AntTaskHolder.getTask();
    }

    // --- TRACE ---

    @Override
    public boolean isTraceEnabled() {
        return true;
    }

    @Override
    public void trace(String msg) {
        final Task t = task();
        if (t != null) {
            t.log(msg, Project.MSG_VERBOSE);
        }
    }

    @Override
    public void trace(String format, Object arg) {
        final Task t = task();
        if (t != null) {
            final FormattingTuple tp = MessageFormatter.format(format, arg);
            t.log(tp.getMessage(), Project.MSG_VERBOSE);
        }
    }

    @Override
    public void trace(String format, Object arg1, Object arg2) {
        final Task t = task();
        if (t != null) {
            final FormattingTuple tp = MessageFormatter.format(format, arg1, arg2);
            t.log(tp.getMessage(), Project.MSG_VERBOSE);
        }
    }

    @Override
    public void trace(String format, Object... arguments) {
        final Task t = task();
        if (t != null) {
            final FormattingTuple tp = MessageFormatter.arrayFormat(format, arguments);
            t.log(tp.getMessage(), Project.MSG_VERBOSE);
        }
    }

    @Override
    public void trace(String msg, Throwable throwable) {
        final Task t = task();
        if (t != null) {
            t.log(msg, throwable, Project.MSG_VERBOSE);
        }
    }

    @Override
    public boolean isTraceEnabled(Marker marker) {
        return isTraceEnabled();
    }

    @Override
    public void trace(Marker marker, String msg) {
        trace(msg);
    }

    @Override
    public void trace(Marker marker, String format, Object arg) {
        trace(format, arg);
    }

    @Override
    public void trace(Marker marker, String format, Object arg1, Object arg2) {
        trace(format, arg1, arg2);
    }

    @Override
    public void trace(Marker marker, String format, Object... argArray) {
        trace(format, argArray);
    }

    @Override
    public void trace(Marker marker, String msg, Throwable throwable) {
        trace(msg, throwable);
    }

    // --- DEBUG ---

    @Override
    public boolean isDebugEnabled() {
        return true;
    }

    @Override
    public void debug(String msg) {
        final Task t = task();
        if (t != null) {
            t.log(msg, Project.MSG_DEBUG);
        }
    }

    @Override
    public void debug(String format, Object arg) {
        final Task t = task();
        if (t != null) {
            final FormattingTuple tp = MessageFormatter.format(format, arg);
            t.log(tp.getMessage(), Project.MSG_DEBUG);
        }
    }

    @Override
    public void debug(String format, Object arg1, Object arg2) {
        final Task t = task();
        if (t != null) {
            final FormattingTuple tp = MessageFormatter.format(format, arg1, arg2);
            t.log(tp.getMessage(), Project.MSG_DEBUG);
        }
    }

    @Override
    public void debug(String format, Object... arguments) {
        final Task t = task();
        if (t != null) {
            final FormattingTuple tp = MessageFormatter.arrayFormat(format, arguments);
            t.log(tp.getMessage(), Project.MSG_DEBUG);
        }
    }

    @Override
    public void debug(String msg, Throwable throwable) {
        final Task t = task();
        if (t != null) {
            t.log(msg, throwable, Project.MSG_DEBUG);
        }
    }

    @Override
    public boolean isDebugEnabled(Marker marker) {
        return isDebugEnabled();
    }

    @Override
    public void debug(Marker marker, String msg) {
        debug(msg);
    }

    @Override
    public void debug(Marker marker, String format, Object arg) {
        debug(format, arg);
    }

    @Override
    public void debug(Marker marker, String format, Object arg1, Object arg2) {
        debug(format, arg1, arg2);
    }

    @Override
    public void debug(Marker marker, String format, Object... arguments) {
        debug(format, arguments);
    }

    @Override
    public void debug(Marker marker, String msg, Throwable throwable) {
        debug(msg, throwable);
    }

    // --- INFO ---

    @Override
    public boolean isInfoEnabled() {
        return true;
    }

    @Override
    public void info(String msg) {
        final Task t = task();
        if (t != null) {
            t.log(msg, Project.MSG_INFO);
        }
    }

    @Override
    public void info(String format, Object arg) {
        final Task t = task();
        if (t != null) {
            final FormattingTuple tp = MessageFormatter.format(format, arg);
            t.log(tp.getMessage(), Project.MSG_INFO);
        }
    }

    @Override
    public void info(String format, Object arg1, Object arg2) {
        final Task t = task();
        if (t != null) {
            final FormattingTuple tp = MessageFormatter.format(format, arg1, arg2);
            t.log(tp.getMessage(), Project.MSG_INFO);
        }
    }

    @Override
    public void info(String format, Object... arguments) {
        final Task t = task();
        if (t != null) {
            final FormattingTuple tp = MessageFormatter.arrayFormat(format, arguments);
            t.log(tp.getMessage(), Project.MSG_INFO);
        }
    }

    @Override
    public void info(String msg, Throwable throwable) {
        final Task t = task();
        if (t != null) {
            t.log(msg, throwable, Project.MSG_INFO);
        }
    }

    @Override
    public boolean isInfoEnabled(Marker marker) {
        return isInfoEnabled();
    }

    @Override
    public void info(Marker marker, String msg) {
        info(msg);
    }

    @Override
    public void info(Marker marker, String format, Object arg) {
        info(format, arg);
    }

    @Override
    public void info(Marker marker, String format, Object arg1, Object arg2) {
        info(format, arg1, arg2);
    }

    @Override
    public void info(Marker marker, String format, Object... arguments) {
        info(format, arguments);
    }

    @Override
    public void info(Marker marker, String msg, Throwable throwable) {
        info(msg, throwable);
    }

    // --- WARN ---

    @Override
    public boolean isWarnEnabled() {
        return true;
    }

    @Override
    public void warn(String msg) {
        final Task t = task();
        if (t != null) {
            t.log(msg, Project.MSG_WARN);
        }
    }

    @Override
    public void warn(String format, Object arg) {
        final Task t = task();
        if (t != null) {
            final FormattingTuple tp = MessageFormatter.format(format, arg);
            t.log(tp.getMessage(), Project.MSG_WARN);
        }
    }

    @Override
    public void warn(String format, Object... arguments) {
        final Task t = task();
        if (t != null) {
            final FormattingTuple tp = MessageFormatter.arrayFormat(format, arguments);
            t.log(tp.getMessage(), Project.MSG_WARN);
        }
    }

    @Override
    public void warn(String format, Object arg1, Object arg2) {
        final Task t = task();
        if (t != null) {
            final FormattingTuple tp = MessageFormatter.format(format, arg1, arg2);
            t.log(tp.getMessage(), Project.MSG_WARN);
        }
    }

    @Override
    public void warn(String msg, Throwable throwable) {
        final Task t = task();
        if (t != null) {
            t.log(msg, throwable, Project.MSG_WARN);
        }
    }

    @Override
    public boolean isWarnEnabled(Marker marker) {
        return isWarnEnabled();
    }

    @Override
    public void warn(Marker marker, String msg) {
        warn(msg);
    }

    @Override
    public void warn(Marker marker, String format, Object arg) {
        warn(format, arg);
    }

    @Override
    public void warn(Marker marker, String format, Object arg1, Object arg2) {
        warn(format, arg1, arg2);
    }

    @Override
    public void warn(Marker marker, String format, Object... arguments) {
        warn(format, arguments);
    }

    @Override
    public void warn(Marker marker, String msg, Throwable throwable) {
        warn(msg, throwable);
    }

    // --- ERROR ---

    @Override
    public boolean isErrorEnabled() {
        return true;
    }

    @Override
    public void error(String msg) {
        final Task t = task();
        if (t != null) {
            t.log(msg, Project.MSG_ERR);
        }
    }

    @Override
    public void error(String format, Object arg) {
        final Task t = task();
        if (t != null) {
            final FormattingTuple tp = MessageFormatter.format(format, arg);
            t.log(tp.getMessage(), Project.MSG_ERR);
        }
    }

    @Override
    public void error(String format, Object arg1, Object arg2) {
        final Task t = task();
        if (t != null) {
            final FormattingTuple tp = MessageFormatter.format(format, arg1, arg2);
            t.log(tp.getMessage(), Project.MSG_ERR);
        }
    }

    @Override
    public void error(String format, Object... arguments) {
        final Task t = task();
        if (t != null) {
            final FormattingTuple tp = MessageFormatter.arrayFormat(format, arguments);
            t.log(tp.getMessage(), Project.MSG_ERR);
        }
    }

    @Override
    public void error(String msg, Throwable throwable) {
        final Task t = task();
        if (t != null) {
            t.log(msg, throwable, Project.MSG_ERR);
        }
    }

    @Override
    public boolean isErrorEnabled(Marker marker) {
        return isErrorEnabled();
    }

    @Override
    public void error(Marker marker, String msg) {
        error(msg);
    }

    @Override
    public void error(Marker marker, String format, Object arg) {
        error(format, arg);
    }

    @Override
    public void error(Marker marker, String format, Object arg1, Object arg2) {
        error(format, arg1, arg2);
    }

    @Override
    public void error(Marker marker, String format, Object... arguments) {
        error(format, arguments);
    }

    @Override
    public void error(Marker marker, String msg, Throwable throwable) {
        error(msg, throwable);
    }
}
