Caching ODC's H2 Database
=========================================

Many users of dependency-check ensure that ODC runs as fast as possible by caching
the entire `data` directory, including the H2 database (`odc.mv.db`).

The location of the `data` directory is different for each integration (cli, maven, gradle, etc.), however each
integration allows users to configure this location.

There are two primary strategies used:

Single node database updater with multiple node "readers"
---------------------------------------------------------

Use a single node to build the database using the integration in "update only" mode
(e.g., `--updateOnly` for the cli) and specify the data directory location (see 
the configuration documentation for each integration's configuration).

The `data` directory is then archived somewhere accessible to all nodes, usually using one of two common caching 
strategies:
1. **Use shared disk storage (e.g network mounted)**
 
    Subsequent nodes point directly to the same mounted storage being written to by the single node updater.

2. **Use a common artifact storage location/repository**
 
    Subsequent nodes will download the archived `data` directory before scanning and unpack to the relevant location.

The "reader" nodes are configured with `--noupdate` (or the related configuration to disable the updates in each 
integration) so they are not reliant on outgoing calls.

The cached `data` directory (and H2 database) is generally updated by the single node/process daily in this use 
case - but could be designed with a more frequent update.

This approach is often used when:
- updating of database/cache needs to be centrally controlled/co-ordinated
- internet access is not available to all nodes/users, and perhaps only available centrally or difficult to 
  configure (e.g proxied environments)
- nodes/users of ODC data cannot safely collaborate on a shared cache without affecting one another

Multiple node database updaters collaborating on a common cache location
------------------------------------------------------------------------

Instead of having only a single update node - all nodes are allowed to update the database if necessary. However
the entire `data` directory is zipped and stored in a common location, including the H2 database, `cache`, and in 
some cases cached data from multiple upstream sources.

There are two common caching strategies here:
1. **Use shared disk storage (e.g network mounted)**
    
    Every node is pointed to writeable shared storage, e.g network mounted. ODC creates an update lock file within
    the shared storage when any individual node is updating, and other nodes will wait for the lock to be released.

2. **Use a common artifact storage location/repository**

    Prior to running ODC, each node downloads the latest version of the archived `data` directory from the shared
    artifact storage and unpacks it to the relevant location.
    
    They then execute a scan (with updates enabled) and if successful the updated `data` directory is archived and
    uploaded to the common location for use by the next node.

Since this strategy allows all nodes to update the common cache to be effective
- it does not help if nodes download from the common cache, but dont share the updated cache with others by uploading
- it requires some degree of consistency in how all nodes configure ODC to ensure the cache is not corrupted by others

This approach is usually used when:
- ensuring data is updated more deterministically after validity period expiry is desirable (e.g `nvdValidForHours`)
- configuring ODC with single writer and multiple reader strategies adds excessive friction
- reliance on a centralised updater is undesirable and a more de-centralised approach is useful

Additional Notes
----------------

The `data` directory may also contain cached data from other upstream sources, depending 
on which analyzers are enabled. Ensuring that file modification times are retained during 
archiving and un-archiving will make these safe to cache, which is especially important in
a multi-node update strategy.
