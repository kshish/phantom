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

def geolocate_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
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

    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], callback=filter_out_internal_IPs, name="geolocate_ip_1")

    return

def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_1() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """The container {0} has one or more IPs outside of N.A.
-
{1}

-

Would you like to change container's severity to high?"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "format_1:formatted_data.*",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=1, name="prompt_1", parameters=parameters, response_types=response_types, callback=decision_3)

    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["prompt_1:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        pin_4(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def filter_out_internal_IPs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_out_internal_IPs() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["geolocate_ip_1:action_result.data.*.country_name", "!=", ""],
        ],
        name="filter_out_internal_IPs:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_by_country(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_1() called')
    
    template = """%%
The ip is {0} is from {1}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_by_country:condition_2:geolocate_ip_1:action_result.parameter.ip",
        "filtered-data:filter_by_country:condition_2:geolocate_ip_1:action_result.data.*.country_name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    prompt_1(container=container)

    return

def filter_by_country(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_by_country() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_out_internal_IPs:condition_1:geolocate_ip_1:action_result.data.*.country_name", "==", "United States"],
            ["filtered-data:filter_out_internal_IPs:condition_1:geolocate_ip_1:action_result.data.*.country_name", "==", "Canada"],
            ["filtered-data:filter_out_internal_IPs:condition_1:geolocate_ip_1:action_result.data.*.country_name", "==", "Mexico"],
        ],
        logical_operator='or',
        name="filter_by_country:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        pin_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_out_internal_IPs:condition_1:geolocate_ip_1:action_result.data.*.country_name", "!=", "United States"],
            ["filtered-data:filter_out_internal_IPs:condition_1:geolocate_ip_1:action_result.data.*.country_name", "!=", "Canada"],
            ["filtered-data:filter_out_internal_IPs:condition_1:geolocate_ip_1:action_result.data.*.country_name", "!=", "Mexico"],
        ],
        logical_operator='and',
        name="filter_by_country:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        format_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def pin_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('pin_3() called')

    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_by_country:condition_1:geolocate_ip_1:action_result.data.*.country_name', 'filtered-data:filter_by_country:condition_1:geolocate_ip_1:action_result.parameter.ip'])

    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]
    filtered_results_item_1_1 = [item[1] for item in filtered_results_data_1]

    phantom.pin(container=container, data=filtered_results_item_1_1, message=filtered_results_item_1_0, pin_type="card", pin_style="blue", name=None)

    return

def pin_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('pin_4() called')

    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_by_country:condition_2:geolocate_ip_1:action_result.data.*.country_name', 'filtered-data:filter_by_country:condition_2:geolocate_ip_1:action_result.parameter.ip'])

    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]
    filtered_results_item_1_1 = [item[1] for item in filtered_results_data_1]

    phantom.pin(container=container, data=filtered_results_item_1_1, message=filtered_results_item_1_0, pin_type="card", pin_style="red", name=None)

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    summary_json = phantom.get_summary()
    if 'result' in summary_json:
        for action_result in summary_json['result']:
            if 'action_run_id' in action_result:
                action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                phantom.debug(action_results)

    return