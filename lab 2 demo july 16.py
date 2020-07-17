"""
This playbook demonstrates stuff
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'geolocate_Source_Address' block
    geolocate_Source_Address(container=container)

    return

"""
this geolocate uses the source address CEF field from the container 
"""
def geolocate_Source_Address(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('geolocate_Source_Address() called')

    # collect data for 'geolocate_Source_Address' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'geolocate_Source_Address' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("geolocate ip", parameters=parameters, assets=['maxmind'], callback=filter_1, name="geolocate_Source_Address")

    return

def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('prompt_1() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """Container {0} with source address

{1}

Would you like to set severity to high?"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "format_ip_and_country_for_analyst:formatted_data.*",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_1", parameters=parameters, response_types=response_types, callback=decision_3)

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
        set_severity_set_sensitivity_pin_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2
    set_severity_2(action=action, success=success, container=container, results=results, handle=handle)

    return

def set_severity_set_sensitivity_pin_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('set_severity_set_sensitivity_pin_1() called')

    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_1:geolocate_Source_Address:action_result.data.*.country_name"])

    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    phantom.set_severity(container=container, severity="High")

    phantom.set_sensitivity(container=container, sensitivity="red")

    phantom.pin(container=container, data=filtered_results_item_1_0, message="chris wuz here", pin_type="card", pin_style="red", name=None)

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["geolocate_Source_Address:action_result.data.*.country_name", "!=", ""],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_1:condition_1:geolocate_Source_Address:action_result.data.*.country_name", "!=", "United States"],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_ip_and_country_for_analyst(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def set_severity_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('set_severity_2() called')

    phantom.set_severity(container=container, severity="Low")

    return

def format_ip_and_country_for_analyst(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_ip_and_country_for_analyst() called')
    
    template = """%%
ip  {0} is from {1}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_2:condition_1:geolocate_Source_Address:action_result.parameter.ip",
        "filtered-data:filter_2:condition_1:geolocate_Source_Address:action_result.data.*.country_name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_ip_and_country_for_analyst")

    prompt_1(container=container)

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