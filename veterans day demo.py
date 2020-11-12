"""
This will end up as a comment in the python code for this playbook
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'my_geo' block
    my_geo(container=container)

    return

"""
this is comment in the code
"""
def my_geo(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('my_geo() called')

    # collect data for 'my_geo' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'my_geo' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], callback=filter_out_None_country_names, name="my_geo")

    return

def ask_to_set_severity_to_high(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ask_to_set_severity_to_high() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """The container {0} with description  {1} with severity {2} has ip  outside of the United States. 

{3}

Do you want to set severity to High?"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "container:description",
        "container:severity",
        "format_1:formatted_data",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=1, name="ask_to_set_severity_to_high", parameters=parameters, response_types=response_types, callback=evaluate_response)

    return

def evaluate_response(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('evaluate_response() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["ask_to_set_severity_to_high:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        set_high_severity(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def set_high_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_high_severity() called')

    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:route_ip_by_country_name:condition_1:my_geo:action_result.data.*.country_name'])

    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    phantom.set_severity(container=container, severity="High")

    phantom.pin(container=container, data=filtered_results_item_1_0, message="IP not in United States", pin_type="card", pin_style="red", name=None)

    return

def set_low_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_low_severity() called')

    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:route_ip_by_country_name:condition_2:my_geo:action_result.parameter.ip'])

    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    phantom.set_severity(container=container, severity="Low")

    phantom.set_sensitivity(container=container, sensitivity="amber")

    phantom.comment(container=container, comment="Set to low severity due to internal ip or US based")

    phantom.pin(container=container, data=filtered_results_item_1_0, message="In US", pin_type="card", pin_style="grey", name=None)

    return

def filter_out_None_country_names(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_out_None_country_names() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["my_geo:action_result.data.*.country_name", "!=", ""],
        ],
        name="filter_out_None_country_names:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        route_ip_by_country_name(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_1() called')
    
    template = """%%
The ip {0} is from {1}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_out_None_country_names:condition_1:my_geo:action_result.parameter.ip",
        "filtered-data:filter_out_None_country_names:condition_1:my_geo:action_result.data.*.country_name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    ask_to_set_severity_to_high(container=container)

    return

def route_ip_by_country_name(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('route_ip_by_country_name() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_out_None_country_names:condition_1:my_geo:action_result.data.*.country_name", "!=", "United States"],
        ],
        name="route_ip_by_country_name:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_out_None_country_names:condition_1:my_geo:action_result.data.*.country_name", "==", "United States"],
        ],
        name="route_ip_by_country_name:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        set_low_severity(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

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