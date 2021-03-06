"""
My playbook comments
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'my_geolocate' block
    my_geolocate(container=container)

    return

"""
This geolocates sourceaddress ip blah blah
"""
def my_geolocate(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('my_geolocate() called')

    # collect data for 'my_geolocate' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'my_geolocate' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("geolocate ip", parameters=parameters, assets=['maxmind'], callback=decide_to_prompt, name="my_geolocate")

    return

def decide_to_prompt(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decide_to_prompt() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["my_geolocate:action_result.data.*.country_name", "!=", "United States"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        filter_no_country_result(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def Change_Severity_to_High(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Change_Severity_to_High() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """{2}

Click here to see the container {1} <html>https://antom15.class.splunk.com/container/{0}</html> . Or find it yourself by this name .  Do you want to change severity to high?"""

    # parameter list for template variable replacement
    parameters = [
        "container:id",
        "container:name",
        "format_message:formatted_data.*",
    ]

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No",
                ]
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=2, name="Change_Severity_to_High", parameters=parameters, response_types=response_types, callback=decision_2)

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Change_Severity_to_High:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        set_severity_set_sensitivity_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def set_severity_set_sensitivity_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('set_severity_set_sensitivity_1() called')

    phantom.set_severity(container=container, severity="High")

    phantom.set_sensitivity(container=container, sensitivity="red")
    promote_to_case_2(container=container)

    return

def filter_no_country_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_no_country_result() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["my_geolocate:action_result.data.*.country_name", "!=", ""],
        ],
        name="filter_no_country_result:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_message(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["my_geolocate:action_result.data.*.country_name", "==", ""],
        ],
        name="filter_no_country_result:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        prompt_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def prompt_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('prompt_2() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """The following ip {0} has no country"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_no_country_result:condition_2:my_geolocate:action_result.parameter.ip",
    ]

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "message",
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_2", parameters=parameters, response_types=response_types)

    return

def format_message(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_message() called')
    
    template = """%%
<html><h1>The ip {0} is from {1}, {2}</h1></html>
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_no_country_result:condition_1:my_geolocate:action_result.parameter.ip",
        "filtered-data:filter_no_country_result:condition_1:my_geolocate:action_result.data.*.city_name",
        "filtered-data:filter_no_country_result:condition_1:my_geolocate:action_result.data.*.country_name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_message")

    Change_Severity_to_High(container=container)
    format_5(container=container)

    return

def send_email_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('send_email_4() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_email_4' call
    formatted_data_1 = phantom.get_format_data(name='format_5')

    parameters = []
    
    # build parameters list for 'send_email_4' call
    parameters.append({
        'from': "churyn@splunk.com",
        'to': "churyn@splunk.com",
        'cc': "",
        'bcc': "",
        'subject': "test",
        'body': formatted_data_1,
        'attachments': "",
        'headers': "",
    })

    phantom.act("send email", parameters=parameters, assets=['smtp'], name="send_email_4")

    return

def format_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_5() called')
    
    template = """{0}

Click here <html>https://antom15.class.splunk.com/container/{1} </html>"""

    # parameter list for template variable replacement
    parameters = [
        "format_message:formatted_data.*",
        "container:id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_5")

    send_email_4(container=container)

    return

def promote_to_case_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('promote_to_case_2() called')

    phantom.promote(container=container, template="Data Breach")

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all detals of actions
    # can be collected here.

    summary_json = phantom.get_summary()
    if 'result' in summary_json:
        for action_result in summary_json['result']:
            if 'action_run_id' in action_result:
                action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                phantom.debug(action_results)

    return