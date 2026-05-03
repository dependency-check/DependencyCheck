How to Mount ISO Files for Scanning
===================================

Dependency-Check can be used as one of your tools for vetting software
distributed via an [ISO image](https://en.wikipedia.org/wiki/ISO_image). (See
[Analyzers](../analyzers/) for a list of what types of artifacts
Dependency-Check is capable of scanning.) These disk image files are not a standard archive format, however. Tools must be used that can interpret the contained file system. As will be shown below, Linux, Mac OS X, and recent versions of Windows can be used to mount the image's file system, which can
then be scanned by Dependency-Check.

ISO images are named for the fact that they nearly always contain one of a
pair of international file system standards published by
[ISO](http://www.iso.org/): [ISO 9660](https://en.wikipedia.org/wiki/ISO_9660)
and ISO/IEC 13346, a.k.a. [UDF](https://en.wikipedia.org/wiki/Universal_Disk_Format). Other types of disk images (e.g.,
[VHD](https://en.wikipedia.org/wiki/VHD_%28file_format%29)) are outside the
scope of this article, though the ideas presented here may likely be
successfully applied.

Linux
-----

Assume you've downloaded an ISO image called `foo.iso`, and you want to mount
it at /mnt/foo. (Why /mnt? See the
[Filesystem Hierarchy Standard](http://refspecs.linuxfoundation.org/FHS_3.0/fhs/ch03s12.html).)
First make sure that the mount point exists using `mkdir /mnt/foo`. Then, the
[mount](http://linux.die.net/man/8/mount) command *must be run with root
privileges*. On Debian and Ubuntu Linux, this is accomplished by prefacing the
command with `sudo`.

```sh
$ sudo mount -o loop foo.iso /mnt/foo
```

Next, you can use Dependency-Check's [command line tool](../dependency-check-cli/index.html)
to scan the mount point. When you are finished, run the
[umount](http://linux.die.net/man/8/umount) command with root privileges:

```sh
$ sudo umount -d /mnt/foo
```

This will unmount the file system, and detach the loop device.

Mac OS X
--------

### Using the GUI

Simply double-click on the image file in Mac OS X Finder.

### Using a Terminal Window

Use the [hdiutil](https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man1/hdiutil.1.html)
command.

```sh
$ hdiutil attach foo.iso
```

The output will show the `/dev` entry assigned as well as the mount point,
which is where you may now read the files in the image's file system.

To detach:

```sh
$ hdiutil detach foo.iso
```

Windows
-------

Windows 8 and later versions support mounting ISO images as a virtual drive.

### Using the GUI

1. In *File Explorer*, right-click on "foo.iso".
2. Select "Mount"

File Explorer then redirects to showing the files on your virtual drive. You can then use the [command line tool](dependency-check-cli/) to scan the
virtual drive. When finished, "Windows-E" will open File Explorer showing the various drives on your computer. To eject the virtual drive:

1. Right-click on the virtual drive.
2. Select "Eject"

### Using PowerShell

To mount, use the [Mount-DiskImage](https://technet.microsoft.com/en-us/%5Clibrary/Hh848706%28v=WPS.630%29.aspx)
cmdlet:

```posh
$ Mount-DiskImage -ImagePath C:\Full\Path\to\foo.iso
```

To view all drives (and find your virtual drive), use the
[Get-PSDrive](https://technet.microsoft.com/en-us/library/Hh849796.aspx)
cmdlet:

```posh
$ Get-PSDrive -PSProvider 'FileSystem'
```

To dismount, use the [Dismount-DiskImage](https://technet.microsoft.com/en-us/library/hh848693%28v=wps.630%29.aspx)
cmdlet:

```posh
$ Dismount-DiskImage -ImagePath C:\Full\Path\to\file.iso
```

### Windows 7

Third-party tools exist that can be used to mount ISO images. Without such
tools, it is still possible to burn the ISO image to physical media, and scan
the media:

1. Right-click on "foo.iso"
2. Select "Windows Disc Image Burner"
3. Follow the instructions to burn the image.

### Windows Vista

Just as with Windows 7, you will need a third-party tool to mount an ISO
image. You will also need a third-party tool to burn the image to media.
Many machines are shipped with such a tool included.
