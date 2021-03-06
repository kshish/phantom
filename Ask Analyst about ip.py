"""
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

    phantom.act("geolocate ip", parameters=parameters, assets=['maxmind'], callback=Ask_Analyst_for_advice, name="geolocate_ip_1")

    return

def Ask_Analyst_for_advice(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Ask_Analyst_for_advice() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """do you want to set severity to high on this ip: {0}
it is from: {1}"""

    # parameter list for template variable replacement
    parameters = [
        "geolocate_ip_1:action_result.parameter.ip",
        "geolocate_ip_1:action_result.data.*.country_name",
    ]

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "range",
                "min": 20,
                "max": 30,
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=2, name="Ask_Analyst_for_advice", parameters=parameters, response_types=response_types, callback=decision_2)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Ask_Analyst_for_advice:action_result.summary.responses.0", "==", "No"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        return

    # call connected blocks for 'else' condition 2
    set_severity_2(action=action, success=success, container=container, results=results, handle=handle)

    return

def set_severity_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('set_severity_2() called')

    phantom.set_severity(container=container, severity="High")

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Ask_Analyst_for_advice:action_result.status", "==", "Success"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        decision_1(action=action, success=success, container=container, results=results, handle=handle)
        return

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