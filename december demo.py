"""
my comments
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'geolocate_ip_1' block
    geolocate_ip_1(container=container)

    return

def geolocate_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('geolocate_ip_1() called')

    # collect data for 'geolocate_ip_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'geolocate_ip_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("geolocate ip", parameters=parameters, assets=['maxmind'], callback=filter_out_none, name="geolocate_ip_1")

    return

def Ask_analyst_high_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Ask_analyst_high_severity() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """Container {2}, {3} has the ip {0}  which is in {1}

Do you want to change severity to high?"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:US_or_Not:condition_1:geolocate_ip_1:action_result.parameter.ip",
        "filtered-data:US_or_Not:condition_1:geolocate_ip_1:action_result.data.*.country_name",
        "container:name",
        "container:description",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=1, name="Ask_analyst_high_severity", parameters=parameters, response_types=response_types, callback=decision_2)

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Ask_analyst_high_severity:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        set_severity_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def set_severity_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('set_severity_2() called')

    phantom.set_severity(container=container, severity="High")

    return

def US_or_Not(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('US_or_Not() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_out_none:condition_1:geolocate_ip_1:action_result.data.*.country_name", "!=", "United States"],
        ],
        name="US_or_Not:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Ask_analyst_high_severity(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_out_none:condition_1:geolocate_ip_1:action_result.data.*.country_name", "==", "United States"],
        ],
        name="US_or_Not:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        prompt_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def filter_out_none(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_out_none() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["geolocate_ip_1:action_result.data.*.country_name", "!=", ""],
        ],
        name="filter_out_none:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        US_or_Not(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def prompt_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('prompt_2() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """is in US ip: {0} from {1}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:US_or_Not:condition_2:geolocate_ip_1:action_result.parameter.ip",
        "filtered-data:US_or_Not:condition_2:geolocate_ip_1:action_result.data.*.country_name",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_2", parameters=parameters, response_types=response_types, callback=format_1)

    return

def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('send_email_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_email_1' call
    formatted_data_1 = phantom.get_format_data(name='format_1__as_list')

    parameters = []
    
    # build parameters list for 'send_email_1' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'from': "",
            'to': "churyn@splunk.com",
            'cc': "",
            'bcc': "",
            'subject': "",
            'body': formatted_part_1,
            'attachments': "",
            'headers': "",
        })

    phantom.act("send email", parameters=parameters, assets=['smtp'], name="send_email_1")

    return

def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_1() called')
    
    template = """Container {0} has ips from {1}"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "geolocate_ip_1:action_result.data.*.country_name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    send_email_1(container=container)

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