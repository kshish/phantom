"""
this is a comment
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'my_geolocate' block
    my_geolocate(container=container)

    return

def my_geolocate(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
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

    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], callback=filter_out_internal_IPs, name="my_geolocate")

    return

def set_High_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_High_severity() called')

    phantom.set_severity(container=container, severity="High")
    
    update_data = { "custom_fields": {"country": "Not US", "department": "International"}}
    success, message = phantom.update(container, update_data)
    phantom.debug(container)
    phantom.debug(success)
    phantom.debug(message)
    pin_3(container=container)

    return

def set_low_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_low_severity() called')

    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:route_IPs:condition_2:my_geolocate:action_result.parameter.ip'])

    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    phantom.set_severity(container=container, severity="Low")

    phantom.set_status(container=container, status="Closed")

    phantom.set_sensitivity(container=container, sensitivity="amber")

    phantom.pin(container=container, data=filtered_results_item_1_0, message="Some IPs in U.S.", pin_type="card", pin_style="grey", name=None)

    return

def prompt_to_decide_high_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_to_decide_high_severity() called')
    
    # set user and message variables for phantom.prompt call
    user = "Administrator"
    message = """The {0} 
---------
{1}
--------
Would you like to set severity to high?"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "format_ip_and_country_list:formatted_data.*",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=1, name="prompt_to_decide_high_severity", parameters=parameters, response_types=response_types, callback=decision_2)

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["prompt_to_decide_high_severity:action_result.summary.responses.0", "!=", "No"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        set_High_severity(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def filter_out_internal_IPs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_out_internal_IPs() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["my_geolocate:action_result.data.*.country_name", "!=", ""],
        ],
        name="filter_out_internal_IPs:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        route_IPs(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def format_ip_and_country_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_ip_and_country_list() called')
    
    template = """%%
ip: {0} is from {1}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:route_IPs:condition_1:my_geolocate:action_result.parameter.ip",
        "filtered-data:route_IPs:condition_1:my_geolocate:action_result.data.*.country_name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_ip_and_country_list")

    prompt_to_decide_high_severity(container=container)

    return

def pin_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('pin_3() called')

    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:route_IPs:condition_1:my_geolocate:action_result.data.*.country_name'])

    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    phantom.pin(container=container, data=filtered_results_item_1_0, message="Some IPs not  inside US", pin_type="card", pin_style="red", name=None)
    format_3(container=container)

    return

def route_IPs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('route_IPs() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_out_internal_IPs:condition_1:my_geolocate:action_result.data.*.country_name", "!=", "United States"],
        ],
        name="route_IPs:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_ip_and_country_list(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_out_internal_IPs:condition_1:my_geolocate:action_result.data.*.country_name", "==", "United States"],
        ],
        name="route_IPs:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        set_low_severity(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def format_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_3() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_3")

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