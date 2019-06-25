"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'Make_a_decision' block
    Make_a_decision(container=container)

    return

def Make_a_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Make_a_decision() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """Please make a decision"""

    # response options
    options = {
        "type": "list",
        "choices": [
            "Yes",
            "No",
            "Maybe",
        ]
    }

    phantom.prompt(container=container, user=user, message=message, respond_in_mins=30, name="Make_a_decision", options=options, callback=prompt_2)

    return

def prompt_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('prompt_2() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """The answer from prior prompt is: {0}"""

    # parameter list for template variable replacement
    parameters = [
        "Make_a_decision:action_result.summary.response",
    ]

    phantom.prompt(container=container, user=user, message=message, respond_in_mins=30, name="prompt_2", parameters=parameters)

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