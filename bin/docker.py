# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Entry point for CBMC job on AWS Batch docker container image"""

import datetime
import json
import subprocess
import os
import sys
from pprint import pprint
import time
import shutil
import re

import boto3

import s3
import options
import package

def abort(msg):
    """Abort a docker container"""
    sys.stdout.flush()
    print(msg)
    sys.stdout.flush()
    raise UserWarning(msg)

def install_cbmc(opts):
    """Install CBMC binaries"""
    package.copy('cbmc', opts['pkgbucket'], opts['cbmcpkg'])
    package.install('cbmc', opts['cbmcpkg'], 'cbmc')

def install_viewer(opts):
    """Install the cbmc-viewer tool"""
    package.copy('cbmc-viewer', opts['pkgbucket'], opts['viewerpkg'])
    package.install('cbmc-viewer', opts['viewerpkg'], 'cbmc-viewer')

def get_buckets(opts, copysrc=True):
    """Copy input buckets to container."""

    if copysrc:
        if opts['srctarfile']:
            tarfile = s3.key_name(opts['srctarfile'])
            tardir = os.path.dirname(opts['srcdir'].rstrip('/'))
            s3.copy_object_to_file(
                opts['srctarfile'], tarfile, region=opts['region'])
            try:
                if not os.path.isdir(tardir):
                    os.makedirs(tardir)
            except OSError:
                abort("Failed to make directory {}".format(tardir))
            cmd = ['tar', 'fx', tarfile, '-C', tardir]
            try:
                subprocess.check_call(cmd)
            except subprocess.CalledProcessError:
                abort("Failed to run command {}".format(' '.join(cmd)))
            if not os.path.isdir(opts['srcdir']):
                abort("Failed to create {} by untarring {}"
                      .format(opts['srcdir'], opts['srctarfile']))
        else:
            s3.sync_bucket_to_directory(opts['srcbucket'], opts['srcdir'])
            # make scripts in the source tree executable
            subprocess.check_call(['chmod', '+x', '-R', opts['srcdir']])
    s3.sync_bucket_to_directory(opts['wsbucket'], opts['wsdir'])
    s3.sync_bucket_to_directory(opts['outbucket'], opts['wsdir'])

def put_buckets(opts):
    """Copy container output to bucket."""

    s3.sync_directory_to_bucket(opts['wsdir'], opts['outbucket'])

def checkpoint_file(filename, fileobj, s3path, region):
    """Write a checkpoint of an open file to a bucket"""

    ckptname = "chkpt-{}".format(filename)
    match = re.match(r'(.+)\.([^.]+)', filename)
    if match:
        ckptname = "{}-chkpt.{}".format(match.group(1), match.group(2))

    fileobj.flush()
    shutil.copyfile(filename, ckptname)
    s3.copy_file_to_object(
        ckptname, "{}/{}".format(s3path, ckptname), region=region)

def checkpoint_performance(logfile, s3path, taskname, region):
    """Write performance information to a logfile in a bucket"""

    gmt = time.gmtime()
    timestamp = ("{:04d}{:02d}{:02d}-{:02d}{:02d}{:02d}"
                 .format(gmt.tm_year, gmt.tm_mon, gmt.tm_mday,
                         gmt.tm_hour, gmt.tm_min, gmt.tm_sec))
    output = subprocess.check_output(['ps', 'ux'])
    cbmc_ps_line = None
    with open(logfile, "a") as logobj:
        logobj.write("\n{}\n".format(timestamp))
        for line in output.split('\n'):
            if 'USER' in line:
                logobj.write(line[:80]+'\n')
            elif 'cbmc' in line:
                logobj.write(line[:80]+'\n')
                cbmc_ps_line = line.split()
    s3.copy_file_to_object(
        logfile, "{}/{}".format(s3path, logfile), region=region)

    if not cbmc_ps_line:
        return

    client = boto3.client('cloudwatch', region_name=region)
    cloudwatch_timestamp = str(
        datetime.datetime.fromtimestamp(time.mktime(gmt)))
    client.put_metric_data(
        Namespace='CBMC-Batch',
        MetricData=[
            {
                'MetricName': 'CPU [%]',
                'Dimensions': [{'Name': 'Job', 'Value': taskname}],
                'Timestamp': cloudwatch_timestamp,
                'Value': float(cbmc_ps_line[2]),
                'Unit': 'Percent'
            },
            {
                'MetricName': 'Memory [%]',
                'Dimensions': [{'Name': 'Job', 'Value': taskname}],
                'Timestamp': cloudwatch_timestamp,
                'Value': float(cbmc_ps_line[3]),
                'Unit': 'Percent'
            },
            {
                'MetricName': 'Memory [MB]',
                'Dimensions': [{'Name': 'Job', 'Value': taskname}],
                'Timestamp': cloudwatch_timestamp,
                'Value': float(cbmc_ps_line[4]) / 1024.0,
                'Unit': 'Megabytes'
            }
        ])


def run_command(command, outfile, errfile, psfile, opts, delay=10):
    """Run command in container"""

    # pylint: disable=too-many-arguments

    cwd = os.getcwd()
    os.chdir(opts['wsdir'])

    sys.stdout.flush()
    print("command = "+" ".join(command))
    print("outfile = "+outfile)
    print("errfile = "+errfile)
    print("psfile = "+psfile)
    print("options = ")
    pprint(opts)
    print("cwd = "+os.getcwd())
    print("PATH = "+os.environ['PATH'])
    sys.stdout.flush()

    print("Running command: {}".format(' '.join(command)))

    with open(outfile, "w") as outobj, open(errfile, "w") as errobj:
        popen = subprocess.Popen(command, universal_newlines=True,
                                 stdout=outobj, stderr=errobj)

        path = opts['outbucket']
        taskname = opts['taskname']
        region = opts['region']
        while popen.poll() is None:
            checkpoint_file(outfile, outobj, path, region)
            checkpoint_file(errfile, errobj, path, region)
            checkpoint_performance(psfile, path, taskname, region)
            time.sleep(delay)

    print("Command returned error code {}: {}".format(popen.returncode,
                                                      ' '.join(command)))
    os.chdir(cwd)

def launch_build(opts):
    """Launch the build step"""

    install_cbmc(opts)
    get_buckets(opts)
    print("Launching Build")
    cmd = ['make', 'goto']
    run_command(cmd, 'build.txt', 'build-err.txt', 'build-ps.txt', opts)
    print("Finished Build")
    put_buckets(opts)

def launch_property(opts):
    """Launch the property step"""

    install_cbmc(opts)
    get_buckets(opts, copysrc=False)
    print("Launching Property")

    cmd = ['cbmc', opts['goto']]
    cmd += options.options_dict2words(opts['cbmcflags'])
    cmd += ['--trace']
    run_command(cmd, 'cbmc.txt', 'cbmc-err.txt', 'cbmc-ps.txt', opts)

    cmd = ['cbmc', opts['goto']]
    cmd += options.options_dict2words(opts['cbmcflags'])
    cmd += ['--show-properties', '--xml-ui']
    run_command(cmd, 'property.xml', 'property-err.txt', 'property-ps.txt',
                opts)

    print("Finished Property")
    put_buckets(opts)

def launch_coverage(opts):
    """Launch the coverage step"""

    install_cbmc(opts)
    get_buckets(opts, copysrc=False)
    print("Launching Coverage")

    cmd = ['cbmc', opts['goto']]
    # CBMC forbids --unwinding-assertions with --cover
    cmd += [opt
            for opt in options.options_dict2words(opts['cbmcflags'])
            if not opt in ['--unwinding-assertions',
                           '--trace',
                           '--stop-on-fail']]
    cmd += ['--cover', 'location', '--xml-ui']
    run_command(cmd, 'coverage.xml', 'coverage-err.txt', 'coverage-ps.txt',
                opts)

    print("Finished Coverage")
    put_buckets(opts)

def launch_report(opts):
    """Launch the report step"""

    install_cbmc(opts)
    install_viewer(opts)
    get_buckets(opts)
    print("Launching Report")

    cmd = ['cbmc-viewer',
           '--srcdir', opts['srcdir'],
           '--htmldir', 'html',
           '--goto', opts['goto'],
           '--result', 'cbmc.txt',
           '--property', 'property.xml',
           '--block', 'coverage.xml',
           '--blddir', opts['blddir'],
           '--json-summary', 'summary.json'
          ]
    run_command(cmd, 'report.txt', 'report-err.txt', 'report-ps.txt', opts)

    print("Finished Report")
    put_buckets(opts)

    summary = None
    with open(os.path.join(opts['wsdir'], 'summary.json'), 'r') as j:
        summary = json.load(j)
    if not summary.get('coverage'):
        print("Incomplete summary: " + str(summary))
        return

    lines = summary['coverage']['statically-reachable']['lines']
    coverage = (
        float(summary['coverage']['statically-reachable']['hit']) /
        float(lines))
    taskname = opts['taskname']
    client = boto3.client('cloudwatch', region_name=opts['region'])
    client.put_metric_data(
        Namespace='CBMC-Batch',
        MetricData=[
            {
                'MetricName': 'Coverage',
                'Dimensions': [{'Name': 'Job', 'Value': taskname}],
                'Value': coverage * 100.0,
                'Unit': 'Percent'
            },
            {
                'MetricName': 'Lines of Code',
                'Dimensions': [{'Name': 'Job', 'Value': taskname}],
                'Value': lines,
                'Unit': 'None'
            }
        ])


def main():
    """Run the job"""

    def more_than_one(bits):
        """Test for more than one boolean value True."""
        count = 0
        for bit in bits:
            count += int(bit)
        return count > 1

    opts = options.docker_options()

    print("docker options")
    pprint(opts)

    if more_than_one([opts['dobuild'], opts['doproperty'],
                      opts['docoverage'], opts['doreport']]):
        print("Too many commands passed to docker container.")
        return

    if opts['dobuild']:
        print("docker doing build")
        launch_build(opts)
        return

    if opts['doproperty']:
        print("docker doing property")
        launch_property(opts)
        return

    if opts['docoverage']:
        print("docker doing coverage")
        launch_coverage(opts)
        return

    if opts['doreport']:
        print("docker doing report")
        launch_report(opts)
        return

    print("docker done")

if __name__ == "__main__":
    main()
