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

    phantom.promote(container=container, template="Data Breach")
    Fixed_sourceDNS(container=container)

    return

def Fixed_sourceDNS(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Fixed_sourceDNS() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceDnsDomain", "!=", ""],
        ],
        name="Fixed_sourceDNS:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Fixed_File_Path(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Fixed_File_Path(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Fixed_File_Path() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.filePath", "!=", ""],
        ],
        name="Fixed_File_Path:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Fixed_address(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Fixed_address(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Fixed_address() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationAddress", "!=", ""],
        ],
        name="Fixed_address:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Get_Country_Name(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_1() called')
    
    template = """A file has been determined pottentially malicious. 

Case link: {0}
Event Name: {1}
Description: {2}
Source URL: {3}
Target Server IP:: {4}
Suspicious File Path: {5}
Country Name: {6}"""

    # parameter list for template variable replacement
    parameters = [
        "container:url",
        "container:name",
        "container:description",
        "filtered-data:Fixed_sourceDNS:condition_1:artifact:*.cef.sourceDnsDomain",
        "filtered-data:Fixed_address:condition_1:artifact:*.cef.destinationAddress",
        "filtered-data:Fixed_File_Path:condition_1:artifact:*.cef.filePath",
        "Get_Country_Name:custom_function:cuntryName",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    send_email_1(container=container)

    return

def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('send_email_1() called')

    # collect data for 'send_email_1' call
    formatted_data_1 = phantom.get_format_data(name='format_1')

    parameters = []
    
    # build parameters list for 'send_email_1' call
    parameters.append({
        'body': formatted_data_1,
        'from': "edu-labserver@splunk.com",
        'attachments': "",
        'to': "churyn@splunk.com",
        'cc': "",
        'bcc': "",
        'headers': "",
        'subject': "New Case Created",
    })

    phantom.act("send email", parameters=parameters, assets=['smtp'], name="send_email_1")

    return

def Get_Country_Name(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Get_Country_Name() called')
    input_parameter_0 = ""

    Get_Country_Name__cuntryName = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    data = phantom.get_object(key='country_name_Email_Notify', container_id=container['id'])
    Get_Country_Name__countryName = data[0]['value']['value']
    # clear object db phantom.clear_object(key='country_name_Email_Notify',container_id=container['id'])
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Get_Country_Name:cuntryName', value=json.dumps(Get_Country_Name__cuntryName))
    format_1(container=container)

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