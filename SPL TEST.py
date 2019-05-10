"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'run_Splunk_SPL' block
    run_Splunk_SPL(container=container)

    return

"""
Counting errors
"""
def run_Splunk_SPL(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('run_Splunk_SPL() called')

    # collect data for 'run_Splunk_SPL' call

    parameters = []
    
    # build parameters list for 'run_Splunk_SPL' call
    parameters.append({
        'query': "index=* OR index=_* error | stats count",
        'display': "",
    })

    phantom.act("run query", parameters=parameters, assets=['splunk'], callback=prompt_1, name="run_Splunk_SPL")

    return

def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('prompt_1() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """status {0}
message {1}
raw {2}
{3}"""

    # parameter list for template variable replacement
    parameters = [
        "run_Splunk_SPL:action_result.message",
        "run_Splunk_SPL:action_result.message",
        "run_Splunk_SPL:action_result.data.*._raw",
        "run_Splunk_SPL:artifact:*.cef.deviceProcessName",
    ]

    phantom.prompt(container=container, user=user, message=message, respond_in_mins=30, name="prompt_1", parameters=parameters)

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