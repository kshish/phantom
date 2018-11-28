"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'promote_to_case_1' block
    promote_to_case_1(container=container)

    return

def promote_to_case_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('promote_to_case_1() called')

    phantom.promote(container=container, template="Response Template 1")
    filter_1(container=container)

    return

def Format_email_body(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Format_email_body() called')
    
    template = """A file has been detected that's bad. A case has been created for this event Click {0} to access.

Event Name: {1}
Description: {2}
Source URL:{3}"""

    # parameter list for template variable replacement
    parameters = [
        "container:url",
        "container:name",
        "container:description",
        "filtered-data:filter_1:condition_1:artifact:*.cef.sourceDnsDomain",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_email_body")

    get_data_1(container=container)

    return

def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('send_email_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_email_1' call
    formatted_data_1 = phantom.get_format_data(name='Format_email_body')

    parameters = []
    
    # build parameters list for 'send_email_1' call
    parameters.append({
        'body': formatted_data_1,
        'from': "edu-tech@splunk.com ",
        'attachments': "",
        'to': "churyn@splunk.com",
        'cc': "",
        'bcc': "",
        'headers': "",
        'subject': "New Case Created",
    })

    phantom.act("send email", parameters=parameters, assets=['smtp'], name="send_email_1")

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceDnsDomain", "!=", None],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_email_body(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def get_data_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('get_data_1() called')

    # collect data for 'get_data_1' call

    parameters = []
    
    # build parameters list for 'get_data_1' call
    parameters.append({
        'headers': "",
        'location': "/rest/ph_user/1",
        'verify_certificate': False,
    })

    phantom.act("get data", parameters=parameters, assets=['local'], callback=Extract_email_address, name="get_data_1")
    phantom.debug("inside get data rest api")

    return

def Extract_email_address(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Extract_email_address() called')
    
    template = """parsed data {0}
status {1}
response {2}
summary status {3}
message {4}"""

    # parameter list for template variable replacement
    parameters = [
        "get_data_1:action_result.data.*.parsed_response_body",
        "get_data_1:action_result.status",
        "get_data_1:action_result.data.*.response_body",
        "get_data_1:action_result.summary.status_code",
        "get_data_1:action_result.message",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Extract_email_address")
    phantom.debug(container)
    format_3(container=container)

    return

def format_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_3() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "Extract_email_address:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_3")
    phantom.debug("formated data from email extract")
    phantom.debug(parameters)
    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all detals of actions 
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return