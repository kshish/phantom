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

def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('prompt_1() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """The container {0}

{1}

Do you want to set severity to high?"""

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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=2, name="prompt_1", parameters=parameters, response_types=response_types, callback=decision_2)

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
        set_severity_4(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def set_severity_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('set_severity_4() called')

    phantom.set_severity(container=container, severity="High")
    playbook_chris_Child_playbook_1(container=container)

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
        format_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def join_filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_filter_1() called')
    
    # if the joined function has already been called, do nothing
    #if phantom.get_run_data(key='join_filter_1_called'):
    #    return

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'my_geolocate' ]):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_filter_1_called', value='filter_1')
        
        # call connected block "filter_1"
        filter_1(container=container, handle=handle)
    
    return

def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_1() called')
    
    template = """%%
ip is {0} is from {1}.
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_1:my_geolocate:action_result.parameter.ip",
        "filtered-data:filter_1:condition_1:my_geolocate:action_result.data.*.country_name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    prompt_1(container=container)

    return

def playbook_chris_Child_playbook_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('playbook_chris_Child_playbook_1() called')
    
    # call playbook "chris/Child playbook", returns the playbook_run_id
    playbook_run_id = phantom.playbook("chris/Child playbook", container=container, name="playbook_chris_Child_playbook_1", callback=call_api_5)

    return

def call_api_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('call_api_5() called')
    
    action_0(container=container)

    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.cn3Label", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        return

    return

def action_0(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('action_0() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    phantom.act("<undefined>", parameters=parameters, name="action_0")

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