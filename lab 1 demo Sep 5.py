"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'geolocate_destination_address' block
    geolocate_destination_address(container=container)

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

    phantom.act("geolocate ip", parameters=parameters, assets=['maxmind'], callback=join_decide_country_of_ip, name="geolocate_source_address")

    return

def decide_country_of_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decide_country_of_ip() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["geolocate_source_address:action_result.data.*.country_name", "==", "United States"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        Set_to_low_severity(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2
    filter_1(action=action, success=success, container=container, results=results, handle=handle)

    return

def join_decide_country_of_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_decide_country_of_ip() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_decide_country_of_ip_called'):
        return

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'geolocate_source_address' ]):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_decide_country_of_ip_called', value='decide_country_of_ip')
        
        # call connected block "decide_country_of_ip"
        decide_country_of_ip(container=container, handle=handle)
    
    return

def Set_to_low_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Set_to_low_severity() called')

    phantom.set_severity(container=container, severity="Low")
    join_prompt_1(container=container)

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

    phantom.act("geolocate ip", parameters=parameters, assets=['maxmind'], callback=join_decide_country_of_ip, name="geolocate_destination_address")

    return

def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('prompt_1() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """The severity of this {1} container owned by {2} has been updated to {0}

The other analyst answered: {3}"""

    # parameter list for template variable replacement
    parameters = [
        "container:severity",
        "container:description",
        "container:owner_name",
        "Ask_analyst_to_set_high_severity:action_result.summary.responses.0",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_1", parameters=parameters, response_types=response_types)

    return

def join_prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_prompt_1() called')

    # check if all connected incoming playbooks or actions are done i.e. have succeeded or failed
    if phantom.completed(playbook_names=['playbook_chris_my_child_playbook_1'], action_names=['geolocate_source_address', 'geolocate_destination_address']):
        
        # call connected block "prompt_1"
        prompt_1(container=container, handle=handle)
    
    return

def Ask_analyst_to_set_high_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Ask_analyst_to_set_high_severity() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """The IP address is from {0}. Do you want to change severity to high?

The filtered data is: {1}"""

    # parameter list for template variable replacement
    parameters = [
        "geolocate_source_address:action_result.data.*.country_name",
        "filtered-data:filter_1:condition_1:geolocate_source_address:action_result.data.*.country_name",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="Ask_analyst_to_set_high_severity", parameters=parameters, response_types=response_types, callback=decision_5)

    return

def decision_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_5() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Ask_analyst_to_set_high_severity:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        playbook_chris_my_child_playbook_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["geolocate_source_address:action_result.data.*.country_name", "!=", ""],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Ask_analyst_to_set_high_severity(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def playbook_chris_my_child_playbook_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('playbook_chris_my_child_playbook_1() called')
    
    # call playbook "chris/my child playbook", returns the playbook_run_id
    playbook_run_id = phantom.playbook("chris/my child playbook", container=container, name="playbook_chris_my_child_playbook_1", callback=join_prompt_1)

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