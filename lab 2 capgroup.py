"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'geolocate_source_address' block
    geolocate_source_address(container=container)

    return

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

    phantom.act("geolocate ip", parameters=parameters, assets=['maxmind'], callback=filter_1, name="geolocate_source_address")

    return

def set_severity_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('set_severity_5() called')

    phantom.set_severity(container=container, severity="Super high")

    return

def Ask_Analyst_to_set_Super_High_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Ask_Analyst_to_set_Super_High_severity() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """The ip {4} is in {1}, {0}

The current severity of \"{2}\" is {3}
Do you want to set severity to Super High?
Country: {1}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_1:geolocate_source_address:action_result.data.*.country_name",
        "filtered-data:filter_1:condition_1:geolocate_source_address:action_result.data.*.city_name",
        "container:name",
        "container:severity",
        "filtered-data:filter_1:condition_1:geolocate_source_address:action_result.parameter.ip",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=2, name="Ask_Analyst_to_set_Super_High_severity", parameters=parameters, response_types=response_types, callback=decision_4)

    return

def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_4() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Ask_Analyst_to_set_Super_High_severity:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        set_severity_5(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["geolocate_source_address:action_result.data.*.country_name", "!=", "United States"],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Ask_Analyst_to_set_Super_High_severity(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

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