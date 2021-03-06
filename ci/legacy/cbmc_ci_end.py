# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Lambda function invoked in response to a Batch job changing state."""

from cbmc_ci_github import update_status

import re
import boto3
import os
import traceback

# S3 Bucket name for storing CBMC Batch packages and outputs
bkt = os.environ['S3_BKT']


def read_from_s3(s3_path):
    """Read from a file in S3 Bucket

    For getting bookkeeping information from the S3 bucket.
    """
    s3 = boto3.client('s3')
    return s3.get_object(Bucket=bkt, Key=s3_path)['Body'].read()


class Job_name_info(object):

    def __init__(self, job_name):
        job_name_match = self.check_job_name(job_name)
        if (job_name_match):
            self.is_cbmc_batch_property_job = True
            self.job_name = job_name_match.group(1)
            self.timestamp = job_name_match.group(2)
        else:
            self.is_cbmc_batch_property_job = False

    @staticmethod
    def check_job_name(job_name):
        """Check job_name to see if it matches CBMC Batch naming conventions"""
        job_name_pattern = "([\S]+)"
        timestamp_pattern = "(\S{16})"
        pattern = job_name_pattern + timestamp_pattern + "-property$"
        res = re.search(pattern, job_name)
        return res

    def get_s3_dir(self):
        """Get s3 bucket directory based on CBMC Batch naming conventions"""
        return self.job_name + self.timestamp

    def get_job_dir(self):
        """
        Get the job directory (in the repo) based on CBMC Batch naming
        conventions.
        """
        return self.job_name


def lambda_handler(event, context):
    """
    Update the status of the GitHub commit appropriately depending on CBMC
    output.

    CBMC output is found in the S3 Bucket for CBMC Batch.

    While the lambda function gets triggered after any Batch job changes
    status, it should only perform an action when the status is "SUCCEEDED" or
    "FAILED" for a "-property" job generated by CBMC Batch.

    The event format from AWS Batch Event is here:
    https://docs.aws.amazon.com/batch/latest/userguide/batch_cwe_events.html
    """
    job_name = event["detail"]["jobName"]
    status = event["detail"]["status"]
    job_name_info = Job_name_info(job_name)
    if ((status == "SUCCEEDED" or status == "FAILED") and
            job_name_info.is_cbmc_batch_property_job):
        s3_dir = job_name_info.get_s3_dir()
        job_dir = job_name_info.get_job_dir()
        # Prepare description for GitHub status update
        desc = "CBMC Batch job " + s3_dir + " " + status
        # Get bookkeeping information about commit
        repo_id = int(read_from_s3(s3_dir + "/repo_id.txt"))
        sha = read_from_s3(s3_dir + "/sha.txt")
        try:
            # Get expected output substring
            expected = read_from_s3(s3_dir + "/expected.txt")
            # Get CBMC output
            cbmc = read_from_s3(s3_dir + "/out/cbmc.txt")
            if expected in cbmc:
                print "Expected Verification Result"
                update_status("success", job_dir, s3_dir, desc, repo_id, sha)
            else:
                print "Unexpected Verification Result"
                update_status("failure", job_dir, s3_dir, desc, repo_id, sha)
        except Exception as e:
            traceback.print_exc()
            # CBMC Error
            desc += ": CBMC Error"
            print desc
            update_status("error", job_dir, s3_dir, desc, repo_id, sha)
            raise e
    else:
        print "No action for " + job_name + ": " + status

    return None
