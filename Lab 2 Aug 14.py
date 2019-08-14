"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'geolocate_source_address' block
    geolocate_source_address(container=container)

    # call 'geolocate_destination_address' block
    geolocate_destination_address(container=container)

    return

"""
This would be technical comment for the developer
"""
def geolocate_source_address(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('geolocate_source_address() called')

    # collect data for 'geolocate_source_address' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'geolocate_source_address' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("geolocate ip", parameters=parameters, assets=['maxmind'], callback=decision_2, name="geolocate_source_address")

    return

def geolocate_destination_address(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('geolocate_destination_address() called')

    # collect data for 'geolocate_destination_address' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'geolocate_destination_address' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("geolocate ip", parameters=parameters, assets=['maxmind'], name="geolocate_destination_address")

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["geolocate_source_address:action_result.data.*.country_name", "==", "United States"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        prompt_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2
    prompt_2(action=action, success=success, container=container, results=results, handle=handle)

    return

def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('prompt_1() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """The source ip is in United States do you want to change severity to high?"""

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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_1", response_types=response_types, callback=decision_3)

    return

def prompt_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('prompt_2() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """Country name: {0}"""

    # parameter list for template variable replacement
    parameters = [
        "geolocate_source_address:action_result.data.*.country_name",
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

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["prompt_1:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        set_severity_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def set_severity_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('set_severity_1() called')

    phantom.set_severity(container=container, severity="High")

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