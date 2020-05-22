"""
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
this is my geolocate action that  lahbaldblhadflhadl;kadfgnsad
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

    phantom.act("geolocate ip", parameters=parameters, assets=['maxmind'], callback=determines_US, name="my_geolocate")

    return

def set_high_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('set_high_severity() called')

    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:Filter_out_None_country:condition_1:my_geolocate:action_result.parameter.ip"])

    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    phantom.set_severity(container=container, severity="High")

    phantom.pin(container=container, data=filtered_results_item_1_0, message="IP not in US", pin_type="card", pin_style="red", name=None)

    return

def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('prompt_1() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """The container {0} is not in the United States.  It has an ip address of {1} from {2}

Container's severity is {3}. Would you like to set severity to high?"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "filtered-data:Filter_out_None_country:condition_1:my_geolocate:action_result.parameter.ip",
        "filtered-data:Filter_out_None_country:condition_1:my_geolocate:action_result.data.*.country_name",
        "container:severity",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=1, name="prompt_1", parameters=parameters, response_types=response_types, callback=decision_2)

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["prompt_1:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        set_high_severity(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def Filter_out_None_country(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Filter_out_None_country() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:determines_US:condition_2:my_geolocate:action_result.data.*.country_name", "!=", ""],
        ],
        name="Filter_out_None_country:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        prompt_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def pin_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('pin_3() called')

    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:determines_US:condition_1:my_geolocate:action_result.parameter.ip"])

    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    phantom.pin(container=container, data=filtered_results_item_1_0, message="Artifact is in US", pin_type="card", pin_style="blue", name=None)

    return

def determines_US(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('determines_US() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["my_geolocate:action_result.data.*.country_name", "==", "United States"],
        ],
        name="determines_US:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        pin_3(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["my_geolocate:action_result.data.*.country_name", "!=", "United States"],
        ],
        name="determines_US:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        Filter_out_None_country(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

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