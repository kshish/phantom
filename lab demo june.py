"""
This will show in the comments of python code for this playbook
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'my_geolocate' block
    my_geolocate(container=container)

    return

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

    phantom.act("geolocate ip", parameters=parameters, assets=['maxmind'], callback=filter_1, name="my_geolocate")

    return

def decide_if_in_US(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decide_if_in_US() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_1:condition_1:my_geolocate:action_result.data.*.country_name", "!=", "United States"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        format_ip_and_country_list(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2
    set_low_severity(action=action, success=success, container=container, results=results, handle=handle)

    return

def set_low_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('set_low_severity() called')

    phantom.set_severity(container=container, severity="Low")

    return

def ask_analyst_to_set_high_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('ask_analyst_to_set_high_severity() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """This container has an ip address outside of the United States.

{0}

The container {1} has {2} severity {2}.

Would you like to set severity to high?"""

    # parameter list for template variable replacement
    parameters = [
        "format_ip_and_country_list:formatted_data.*",
        "container:name",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=1, name="ask_analyst_to_set_high_severity", parameters=parameters, response_types=response_types, callback=decision_3)

    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["ask_analyst_to_set_high_severity:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        playbook_chris_my_child_playbook_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def pin_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('pin_3() called')

    phantom.pin(container=container, data="important data here", message="chris wuz here", pin_type="card", pin_style="", name=None)

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
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
        decide_if_in_US(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def format_ip_and_country_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_ip_and_country_list() called')
    
    template = """%%
the ip {0} is in {1}.
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_1:my_geolocate:action_result.parameter.ip",
        "filtered-data:filter_1:condition_1:my_geolocate:action_result.data.*.country_name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_ip_and_country_list")

    ask_analyst_to_set_high_severity(container=container)

    return

def playbook_chris_my_child_playbook_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('playbook_chris_my_child_playbook_1() called')
    
    # call playbook "chris/my child playbook", returns the playbook_run_id
    playbook_run_id = phantom.playbook("chris/my child playbook", container=container)

    pin_3(container=container)

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