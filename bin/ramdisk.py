#!/usr/bin/env python3

"""Ramdisk support for Linux systems.
    Note: tmpfs ram disks have a maximum size, but only use ram up to the amount required by the
    files stored in the ram disk.  Therefore, it is o.k. to create several ram disks and even to
    mount a ram disk underneath another ram disk in terms of memory consumption.

    Note that if the tmpfs RAM disks become too large, they will adversely affect performance by using
    swap space (like any other RAM-resident task), likely making performance very slow.
"""

import os
import sys
import subprocess

def normalize_folders(folders):
    """Normalize folders in a list of folders."""
    return [os.path.abspath(folder) for folder in folders]

def mount_ramdisk(folder, megabytes=1024):
    """Mount a ramdisk on a folder.

    Mount a ramdisk of a size given by megabytes on a folder.
    """
    print("mounting RAM disk at location: {} of size: {}".format(folder, megabytes))
    os.makedirs(folder)
    cmd = ['sudo',
           'mount', '-t', 'tmpfs', '-o', 'size={}M'.format(megabytes), 'tmpfs',
           folder]
    subprocess.check_call(cmd)

def unmount_ramdisk(folder):
    """
    Unmount a ramdisk
    :param folder:
    :return:
    """
    print("unmounting RAM disk at location: {} of size: {}".format(folder, megabytes))
    cmd = ['sudo',
           'umount', folder]
    subprocess.check_call(cmd)

def mount_ramdisks(folders, megabytes=1024):
    """Mount ramdisks on folders.

    Mount a ramdisk of a size given by megabytes on each folder in
    folders, taking care to normalize folder names, ignore duplicates,
    and create the folders in the right order.
    """
    folders = [os.path.abspath(folder) for folder in folders]
    for folder in sorted(set(folders)):
        mount_ramdisk(folder, megabytes)

def unmount_ramdisks(folders):
    """unmount ramdisks on folders.

    unmount a ramdisk of a size given by megabytes on each folder in
    folders, taking care to normalize folder names, ignore duplicates,
    and create the folders in the right order.
    """

    folders = [os.path.abspath(folder) for folder in folders]
    for folder in sorted(set(folders)):
        unmount_ramdisk(folder)

def tasks_using_ramdisk(folder):
    cmd = ['sudo',
           'lsof', '-n', folder]
    subprocess.check_call(cmd)

def tasks_using_ramdisks(folders):
    folders = [os.path.abspath(folder) for folder in folders]
    for folder in sorted(set(folders)):
        tasks_using_ramdisk(folder)


if __name__ == '__main__':
    mount_ramdisks(sys.argv[1:])
