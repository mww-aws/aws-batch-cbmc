# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import logging
import uuid

# Summary entries are used to track the tree of tasks in a complex computation
# and to provide so-called "canonical log entries" that provide a single line summary
# what happened for a particular task.
#
# Tasks can be in three stages in terms of our log entries:
#   LAUNCHED
#   STARTED
#   COMPLETED
#
# The information in a STARTED or COMPLETED entry should be sufficient to identify
# all the log entries associated with that task.  A LAUNCHED task may or may not
# have sufficient information, though we try to provide it.
#
# When a task is LAUNCHED, it is provided with a correlation_list, which is a
# generalization of a correlation identifier (see:
#       https://blog.rapid7.com/2016/12/23/the-value-of-correlation-ids/
#       https://dzone.com/articles/correlation-id-for-logging-in-microservices
# for a discussion of correlation identifiers)
#
# The correlation_chain is a list of correlation ids.  The head of the list
# is the id associated with the root task.  Child correlation ids are generated
# by their parents and "pushed" to the child task in an event.  We use UUIDs
# for uniqueness.

# To extract the portion of the log associated with the canonical entries,
# We separate based on type:
#   For lambdas, in the STARTED node, we store the context aws-request-id that
#   is used in the START and END log entries for the log stream containing
#   the lambda.  If we are not concerned about concurrency, we can just
#   use the START and END entries to find the timestamps and extract the
#   portion of the log in between.  If a container may concurrently execute
#   multiple instances of the same lambda, then this will get extraneous
#   log entries.  You can handle this concurrency by requiring the aws-request-id
#   as a field for all log entries within the lambda, but I am not going
#   to worry about it.
#   the aws-request-id is used as the task-id for lambda.
#
#   For CodeBuild instances, we use the logging stream id returned by
#   start_build().  It is built into the ARN returned by the call.
#   The ARN is used as the task_id (it is passed in the event).
#
#   For AWS Batch, we can use the jobid that is returned by submit-job to
#   find the associated log stream.  In the case of cbmc-batch, we don't have
#   direct access to this information, so we start from job names, then
#   use list-jobs to return the set of job ids associated (there should be
#   a handful: for each cbmc-batch job name, it creates a handful of AWS
#   batch jobs).  For each one, we look up its log stream and proceed.
#
#   The cbmc_ci_end listener is handled specially.  It reports the STARTED
#   and COMPLETED status of cbmc-batch as we don't want to modify cbmc-batch
#   directly (at least, not at the moment).  Rather than recording its own
#   status, it records the status of CBMC batch.

#---------------------------------------------------------------------------
#   Miscellaneous module stuff
#---------------------------------------------------------------------------
UNKNOWN = "UNKNOWN"
STARTED = "STARTED"
IGNORED = "COMPLETED:IGNORED"
SUCCEEDED = "COMPLETED:SUCCEEDED"
FAILED = "COMPLETED:FAILED"
LAUNCH_SUCCEEDED = "LAUNCHED:SUCCEEDED"
LAUNCH_FAILED = "LAUNCHED:FAILED"

def is_completed_status(status):
    return status == SUCCEEDED or status == FAILED or status == IGNORED

def entry_string(task_name, task_id, correlation_list, status, args):
    summary = {}
    summary['task_name'] = task_name
    summary['task_id'] = task_id
    summary['correlation_list'] = correlation_list
    summary['status'] = status
    summary.update(args)
    return json.dumps(summary)


class CLogWriter():
    def __init__(self, task_name, task_id=None, correlation_list=[]):
        # snapshot is defined by a json string or json file
        self.task_name = task_name
        self.task_id = task_id
        self.correlation_list = correlation_list

    @classmethod
    def init_lambda(cls, task_name, event, context):
        task_id = context.aws_request_id
        correlation_list = event.get('correlation_list', [task_id]).copy()
        return cls(task_name = task_name,
            task_id=task_id,
            correlation_list=correlation_list)

    @classmethod
    def init_aws_batch(cls, task_name, task_id, correlation_list):
        return cls(task_name=task_name,
                   task_id = task_id,
                   correlation_list=correlation_list)

    @classmethod
    def init_child(cls, parent, child_task_name, child_task_id):
        child_correlation_list = parent.create_child_correlation_list()
        return cls(task_name=child_task_name,
                   task_id=child_task_id,
                   correlation_list=child_correlation_list)

    # TODO: if we care about lambda concurrency, have all task log messages run
    # TODO: through our log functions that prepend the task_id.
    # def critical(self, msg, *args, **kwargs):
    # def error(self, msg, *args, **kwargs):
    # def warning(self, msg, *args, **kwargs):
    # def info(self, msg, *args, **kwargs):
    # def debug(self, msg, *args, **kwargs):

    def entry_string(self, status, args):
        return entry_string(self.task_name, self.task_id, self.correlation_list, status, args)

    def started(self):
        print(self.entry_string(STARTED, {}))

    def launched(self, status=LAUNCH_SUCCEEDED):
        print(self.entry_string(status, {}))

    def launch_child(self, child_task_name, child_task_id, child_correlation_list, status=LAUNCH_SUCCEEDED):
        print(entry_string(child_task_name, child_task_id, child_correlation_list, status, {}))

    def summary(self, status, event, response):
        args = {'event' : event, 'response': response}
        print(self.entry_string(status, args))


    def get_correlation_list(self):
        return self.correlation_list


    # generate a new UUID to track child.
    def create_child_correlation_list(self):
        child_list = self.correlation_list.copy()
        child_list.append(str(uuid.uuid4()))
        return child_list
