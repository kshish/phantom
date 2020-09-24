"""
This will end up in comments of python script
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

    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], callback=filter_1, name="my_geolocate")

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_1:condition_1:my_geolocate:action_result.data.*.country_name", "!=", "find_artifacts_2:artifact:*.cef.cn2"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        format_ip_and_country_name_list(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    set_low_severity(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def ask_to_set_high_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ask_to_set_high_severity() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """The container named {0} with

{1}

Do you want to set severity to High?"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "format_ip_and_country_name_list:formatted_data.*",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=1, name="ask_to_set_high_severity", parameters=parameters, response_types=response_types, callback=decision_2)

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["ask_to_set_high_severity:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        set_high_severity(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def set_high_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_high_severity() called')

    phantom.set_severity(container=container, severity="High")

    return

def set_low_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_low_severity() called')

    phantom.set_severity(container=container, severity="Low")

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["my_geolocate:action_result.data.*.country_name", "!=", ""],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        find_artifacts_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def format_ip_and_country_name_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_ip_and_country_name_list() called')
    
    template = """%%
ip {0} is in {1}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_1:my_geolocate:action_result.parameter.ip",
        "filtered-data:filter_1:condition_1:my_geolocate:action_result.data.*.country_name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_ip_and_country_name_list")

    ask_to_set_high_severity(container=container)

    return

def find_artifacts_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('find_artifacts_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'find_artifacts_2' call

    parameters = []
    
    # build parameters list for 'find_artifacts_2' call
    parameters.append({
        'values': "country",
        'exact_match': "true",
        'limit_search': False,
        'container_ids': 12,
    })

    phantom.act(action="find artifacts", parameters=parameters, assets=['mylocophantom'], callback=decision_1, name="find_artifacts_2")

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return