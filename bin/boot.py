#!/usr/bin/env python3

# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Create RAM disks, copy cbmc-batch package from S3 and launch it"""

import json

import options
import package
import ramdisk


def boot():
    """Create RAM disks, copy cbmc-batch package from S3 and launch it
        NOTE: RAM disks use only as much memory as consumed by files currently resident.
        The 3GB limit is perhaps excessive but should not lead to problems in practice if
        file sizes are reasonable"""
    opts = options.docker_options()
    print("Booting with options " + json.dumps(opts))

    RAM_DISK_DIRS = [u'cbmc-batch', u'cbmc', u'cbmc-viewer',
                     opts['blddir'], opts['wsdir'], opts['srcdir'], opts['outdir']]
    RAM_DISK_SIZE = 3072
    print("Creating RAM disks: {} with size {} ".format(str(RAM_DISK_DIRS), RAM_DISK_SIZE))
    try:
        ramdisk.mount_ramdisks(RAM_DISK_DIRS, RAM_DISK_SIZE)

        package.copy('cbmc-batch', opts['pkgbucket'], opts['batchpkg'])
        package.install('cbmc-batch', opts['batchpkg'], 'cbmc-batch')
        package.launch('cbmc-batch', 'docker.py', ['--jsons', json.dumps(opts)])
    finally:
        print("Tasks using RAM disks: ")
        ramdisk.tasks_using_ramdisks(RAM_DISK_DIRS)
        print("Unmounting RAM disks")
        ramdisk.unmount_ramdisks(RAM_DISK_DIRS)

if __name__ == "__main__":
    boot()
