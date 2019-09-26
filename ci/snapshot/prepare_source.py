#!/usr/bin/env python3

# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import argparse
import subprocess
import logging
import datetime
from urllib.parse import urlparse
import json
import sys
import traceback

import boto3

import cbmc_ci_start
import cbmc_ci_github
import clog_writert

# Too hard to install, just run git as a subprocess
# import pygit2

################################################################

# All proofs are under one of these directories
PROOF_MARKERS = ['cbmc/proofs', '.cbmc-batch/jobs']

# Scripts run before taring up the repository
MAKE_COMMON_MAKEFILE = 'make_common_makefile.py'
MAKE_PROOF_MAKEFILES = 'make_proof_makefiles.py'
PREPARE_FILE = 'prepare.py'

# Expected name for CBMC Batch yaml
YAML_NAME = "cbmc-batch.yaml"

# S3 Bucket name for storing CBMC Batch packages and outputs
# FIX: Lambdas put S3_BKT in env, CodeBuild puts S3_BUCKET in env.
BKT = os.environ.get('S3_BKT') or os.environ.get('S3_BUCKET')

################################################################
# argument parsing

def get_arguments():
    parser = argparse.ArgumentParser(
        description='Download source code and prepare it for CBMC Batch')

    ################################################################
    # AWS profile
    parser.add_argument(
        '--profile',
        metavar='PROFILE',
        help='The AWS account profile.'
    )

    ################################################################
    # GitHub names
    parser.add_argument(
        '--repository',
        metavar='REPO',
        help="""
        The URL for cloning the GitHub repository.
        As in 'git clone REPO'.
        """
    )
    parser.add_argument(
        '--branch',
        metavar='BRANCH',
        help="""
        The name of the branch to check out of the GitHub repository.
        As in 'git checkout BRANCH'.
        """
    )
    parser.add_argument(
        '--sha',
        metavar='SHA',
        help="""
        The SHA for the branch to check out of the GitHub repository.
        """
    )
    parser.add_argument(
        '--is-draft',
        action='store_true',
        help="""
        Mark pull request as being in "Draft" status.
        """
    )
    parser.add_argument(
        '--id',
        metavar='ID',
        help="""
        The ID for the GitHub repository.
        """
    )

    ################################################################
    # S3 paths
    parser.add_argument(
        '--bucket',
        metavar='BKT',
        help='S3 bucket name.'
    )
    parser.add_argument(
        '--tarfile-path',
        metavar="PATH",
        help='S3 path to folder for tarfile relative to BKT.'
    )
    parser.add_argument(
        '--tarfile-name',
        metavar="NAME",
        help='Filename for the tar file.'
    )

    ################################################################
    # Logging level
    parser.add_argument(
        '--logging',
        metavar='LEVEL',
        help="""
        The logging level, should be one of
        DEBUG, INFO, WARNING, ERROR, CRITICAL
        (default: %(default)s)
        """,
        default='INFO'
    )

    ################################################################

    parser.add_argument(
        '--correlation-list',
        metavar='CORRELATION_LIST',
        help="""
        An ID for tracing the invocation back to the original Github event.
        """
    )
    parser.add_argument(
        '--task-id',
        metavar='TASK_ID',
        help="""
        An ID for identifying the current task.
        """
    )

    arg = parser.parse_args()
    if not arg.repository:
        # Environment value could be an empty string
        env = os.environ.get('CBMC_REPOSITORY')
        arg.repository = env if env else None
    if not arg.branch:
        # Environment value could be an empty string
        env = os.environ.get('CBMC_BRANCH')
        arg.branch = env if env else None
    if not arg.sha:
        # Environment value could be an empty string
        env = os.environ.get('CBMC_SHA')
        arg.sha = env if env else None
    if not arg.is_draft:
        # Environment value could be an empty string
        env = os.environ.get('CBMC_IS_DRAFT')
        arg.is_draft = env is not None and env.lower() == "true"
    if not arg.id:
        # Environment value could be an empty string
        env = os.environ.get('CBMC_ID')
        arg.id = env if env else None
    if not arg.bucket:
        arg.bucket = os.environ.get('S3_BUCKET')
    if not arg.tarfile_path:
        # Environment value could be an empty string
        env = os.environ.get('S3_TAR_PATH')
        arg.tarfile_path = env if env else None
    if not arg.tarfile_name:
        arg.tarfile_name = make_tarfile_name(arg.repository, arg.sha)
    if not arg.correlation_list:
        env = os.environ.get('CORRELATION_LIST')
        arg.correlation_list = json.loads(env) if env else []
    if not arg.task_id:
        env = os.environ.get('CODEBUILD_BUILD_ID')
        arg.task_id = env if env else None
    return arg

################################################################
# logging

def debug_json(action, body):
    debug = {'script': os.path.basename(__file__),
             'action': action,
             'body': body}
    return json.dumps(debug)

def script_data(arg):
    debug = {'argv': sys.argv,
             'arg': {key: getattr(arg, key) for key in vars(arg)},
             'S3_BUCKET': os.environ.get('S3_BUCKET'),
             'S3_PKG_PATH': os.environ.get('S3_PKG_PATH'),
             'S3_TAR_PATH': os.environ.get('S3_TAR_PATH'),
             'CBMC_REPOSITORY': os.environ.get('CBMC_REPOSITORY'),
             'CBMC_BRANCH': os.environ.get('CBMC_BRANCH'),
             'CBMC_SHA': os.environ.get('CBMC_SHA'),
             'CBMC_IS_DRAFT': os.environ.get('CBMC_IS_DRAFT')
             }
    return debug

def subprocess_data(cmd, cwd, stdout, stderr):
    debug = {'cmd': ' '.join(cmd),
             'cwd': cwd,
             'stdout': stdout.decode("utf-8").splitlines(),
             'stderr': stderr.decode("utf-8").splitlines()
             }
    return debug

################################################################
# subprocess

def run_command(cmd, cwd=None):
    logging.info('Running "%s" in "%s"', ' '.join(cmd), cwd or '.')
    kwds = {'capture_output': True}
    if cwd:
        kwds['cwd'] = cwd
    result = subprocess.run(cmd, **kwds)
    debug = subprocess_data(cmd, cwd, result.stdout, result.stderr)
    logging.info(debug_json('subprocess', debug))
    result.check_returncode()

################################################################
# github

def repository_name(url):
    name = None
    if url.startswith('git@'):
        # git uses nonstandard url format
        name = url.split(':')[-1]
    else:
        name = urlparse(url).path
    if name is None:
        return None
    if name.endswith('.git'):
        name = name[:-4]
    return name.strip('/')

def repository_basename(url):
    return repository_name(url).replace('/', '-')

def clone_repository(url, srcdir):
    cmd = ['git', 'clone', '--recurse-submodules', url, srcdir]
    run_command(cmd)

    # Fetch the pull request data in addtion to the head data that
    # comes by default with the git clone
    cmd = ['git', 'config', '--add', 'remote.origin.fetch',
           '+refs/pull/*/head:refs/remotes/origin/pr/*']
    run_command(cmd, srcdir)
    cmd = ['git', 'fetch', 'origin']
    run_command(cmd, srcdir)

def checkout_repository(sha=None, branch=None, srcdir=None):
    checkout = sha or branch
    if checkout is None:
        return
    cmd = ['git', 'checkout', checkout]
    run_command(cmd, srcdir)

################################################################

def find_proof_groups(group_names, root='.'):
    """Find CBMC proof group directories under root.

    CBMC proofs are grouped together under directories with names like
    'cbmc/proofs' and '.cbmc-batch/jobs' given by the list group_names.
    Find all such directories under root.
    """

    return [path
            for path, _, _ in os.walk(root)
            if any([path.endswith(os.path.sep + suffix)
                    for suffix in group_names])]

def find_proof_directories(groupdir, relative=True):
    """Find CBMC proof directories under a proof group directory groupdir.

    A CBMC proof requires a file named 'cbmc-batch.yaml' that gives
    parameters for running that proof under CBMC Batch.  Find all such
    directories under groupdir.
    """

    prefix_length = len(groupdir)+1 if relative else 0
    return [dir[prefix_length:]
            for dir, _, files in os.walk(groupdir)
            if YAML_NAME in files]

def find_proofs(group_names, root='.'):
    """Return (proof-group, proof-directory) pairs for CBMC proofs under root.

    The proof-group is a full path, proof-directory is relative to proof-group.
    """

    return [(groupdir, proofdir)
            for groupdir in find_proof_groups(group_names, root)
            for proofdir in find_proof_directories(groupdir)]

def find_tasks(group_names, root='.'):
    """Return (proof-name, proof-directory) pairs for CBMC proofs under topdir.

    For any given proof, CBMC Batch needs the name of the proof and the
    directory containing the proof.
    """

    return [(os.path.split(proofdir)[1], os.path.join(groupdir, proofdir))
            for (groupdir, proofdir) in find_proofs(group_names, root)]

################################################################
# tar files

def make_tarfile_name(repository, sha=None):
    now = datetime.datetime.utcnow()
    filename = repository_basename(repository)
    filename += '-{:04}{:02}{:02}-{:02}{:02}{:02}'.format(
        now.year, now.month, now.day, now.hour, now.minute, now.second)
    if sha:
        filename += '-{}'.format(sha.lower())
    filename += '.tar.gz'
    return filename

def generate_tarfile(tarfile, srcdir):
    # Just a simple tar, not worth the tarfile module
    cmd = ['tar', 'fcz', tarfile, srcdir]
    run_command(cmd)

def upload_tarfile_to_s3(tarfile, bucket, path):
    logging.info("Uploading %s to %s/%s", tarfile, bucket, tarfile)
    s3 = boto3.client('s3')
    key = '{}/{}'.format(path, tarfile) if path else tarfile
    s3.upload_file(Bucket=bucket, Key=key, Filename=tarfile)

################################################################

def generate_cbmc_makefiles(group_names, root):
    for directory in find_proof_groups(group_names, root):
        files = os.listdir(directory)
        if PREPARE_FILE in files:
            cmd = ["python", PREPARE_FILE]
            run_command(cmd, directory)

################################################################
# CBMC Batch

def generate_cbmc_jobs(src, repo_id, repo_sha, is_draft, tarfile, logger):
    # Find (proof-name, proof-directory) pairs for all proofs under src
    tasks = find_tasks(PROOF_MARKERS, src)
    print("{} tasks found".format(len(tasks)))
    pending_exception = None

    for (proofname, proofdir) in tasks:
        # pylint: disable=broad-except
        try:
            # Try to run batch
            (jobname, expected) = cbmc_ci_start.run_batch(
                os.environ['AWS_REGION'], proofdir, src, proofname, tarfile)

            # Log result
            child_correlation_list = logger.create_child_correlation_list()
            logger.launch_child(jobname, None, child_correlation_list)

            cbmc_ci_start.batch_bookkeep(
                ".", repo_id, repo_sha, is_draft, expected, proofname,
                jobname, json.dumps(child_correlation_list))
        except Exception as e:
            # Update commit status to error
            pending_exception = e
            traceback.print_exc()
            cbmc_ci_github.update_status(
                "error", proofname, None,
                "Problem launching verification", repo_id, repo_sha, False)
            print("Error: " + str(e))
            response = {'proofname': proofname,
                        'error' : "Exception: {}; Traceback: {}".format(str(e), traceback.format_exc())}

    if pending_exception is not None:
        raise pending_exception

################################################################

def source_prepare():
    arg = get_arguments()
    logger = clog_writert.CLogWriter("prepare_source:source_prepare", arg.task_id, arg.correlation_list)
    logger.started()
    try:
        logging.basicConfig(level=getattr(logging, arg.logging.upper()),
                            format='%(levelname)s: %(message)s')
        logging.debug(debug_json('invocation', script_data(arg)))

        base_name = repository_basename(arg.repository)
        clone_repository(arg.repository, base_name)
        checkout_repository(arg.sha, arg.branch, base_name)
        generate_cbmc_makefiles(PROOF_MARKERS, base_name)
        generate_tarfile(arg.tarfile_name, base_name)
        upload_tarfile_to_s3(arg.tarfile_name, arg.bucket, arg.tarfile_path)
        generate_cbmc_jobs(
            base_name, arg.id, arg.sha, arg.is_draft, arg.tarfile_name, logger)
        logger.summary(clog_writert.SUCCEEDED, vars(arg), {})
    except Exception as e:
        response = {'error' : "Exception: {}; Traceback: {}".format(str(e), traceback.format_exc())}
        logger.summary(clog_writert.FAILED, vars(arg), response)
        raise e


################################################################

if __name__ == "__main__":
    source_prepare()
