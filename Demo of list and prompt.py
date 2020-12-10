"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'Prompt_for_color' block
    Prompt_for_color(container=container)

    return

def Prompt_for_color(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Prompt_for_color() called')
    
    # set user and message variables for phantom.prompt call
    user = "Administrator"
    message = """Please type in a some value name"""

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "message",
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=1, name="Prompt_for_color", response_types=response_types, callback=decision_2)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_community_string_to_lowercase_1:custom_function_result.data.lowercase_string", "in", "custom_list:colors"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        prompt_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    add_list_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def prompt_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_2() called')
    
    # set user and message variables for phantom.prompt call
    user = "Administrator"
    message = """Yes {0} is in the list also here's a curly brace \"{{0}}\""""

    # parameter list for template variable replacement
    parameters = [
        "cf_community_string_to_lowercase_1:custom_function_result.data.lowercase_string",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_2", parameters=parameters, response_types=response_types)

    return

def add_list_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_list_1() called')

    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_community_string_to_lowercase_1:custom_function_result.data.lowercase_string'], action_results=results)

    custom_function_results_item_1_0 = [item[0] for item in custom_function_results_data_1]

    phantom.add_list("colors", custom_function_results_item_1_0)

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Prompt_for_color:action_result.status", "==", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_community_string_to_lowercase_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def cf_community_string_to_lowercase_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_string_to_lowercase_1() called')
    
    action_results_data_0 = phantom.collect2(container=container, datapath=['Prompt_for_color:action_result.summary.responses.0', 'Prompt_for_color:action_result.parameter.context.artifact_id'], action_results=results )

    parameters = []

    for item0 in action_results_data_0:
        parameters.append({
            'input_string': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/string_to_lowercase", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/string_to_lowercase', parameters=parameters, name='cf_community_string_to_lowercase_1', callback=decision_1)

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