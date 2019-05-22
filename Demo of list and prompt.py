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

def Prompt_for_color(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Prompt_for_color() called')
    
    # set user and message variables for phantom.prompt call
    user = "Administrator"
    message = """Please type in a color name"""

    phantom.prompt(container=container, user=user, message=message, respond_in_mins=30, name="Prompt_for_color", callback=decision_1)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Prompt_for_color:action_result.summary.response", "in", "custom_list:favorite colors"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        prompt_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2
    add_list_pin_1(action=action, success=success, container=container, results=results, handle=handle)

    return

def prompt_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('prompt_2() called')
    
    # set user and message variables for phantom.prompt call
    user = "Administrator"
    message = """Yes it's in the list"""

    # response options
    options = {
        "type": "list",
        "choices": [
            "Yes",
            "No",
        ]
    }

    phantom.prompt(container=container, user=user, message=message, respond_in_mins=30, name="prompt_2", options=options)

    return

def add_list_pin_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('add_list_pin_1() called')

    results_data_1 = phantom.collect2(container=container, datapath=['Prompt_for_color:action_result.summary.response', 'Prompt_for_color:action_result.status'], action_results=results)

    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_1_1 = [item[1] for item in results_data_1]

    phantom.add_list("favorite colors", results_item_1_0)

    phantom.pin(container=container, message=results_item_1_0, data=results_item_1_1, pin_type="card_small", pin_style="purple")

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