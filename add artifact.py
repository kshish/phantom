"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'add_artifact_1' block
    add_artifact_1(container=container)

    return

def add_artifact_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('add_artifact_1() called')

    # collect data for 'add_artifact_1' call

    parameters = []
    
    # build parameters list for 'add_artifact_1' call
    parameters.append({
        'name': "User created artifact",
        'container_id': "",
        'label': "event",
        'source_data_identifier': "chris",
        'cef_name': "deviceCustomString2",
        'cef_value': "chris was here",
        'cef_dictionary': "",
        'contains': "",
    })

    phantom.act("add artifact", parameters=parameters, assets=['local phantom'], name="add_artifact_1")

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