Database Upgrades
=================
If using an external database server, such as MySQL, a DBA must manually perform the
database schema update. In most cases an upgrade requires re-running the initialization script
which will drop the current tables and re-create them. The initialization can be found in the
[github repository](https://github.com/dependency-check/DependencyCheck/tree/main/core/src/main/resources/data).

If you want to use an external database other than one listed in the repo please open an issue on the
[github issue tracker](https://github.com/dependency-check/DependencyCheck/issues) as an initialization and
dialect properties file will likely need to be created.