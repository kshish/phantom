"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'set_severity_1' block
    set_severity_1(container=container)

    return

def set_severity_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('set_severity_1() called')

    phantom.set_severity(container=container, severity="High")
    set_sensitivity_set_status_pin_set_label_2(container=container)

    return

def set_sensitivity_set_status_pin_set_label_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('set_sensitivity_set_status_pin_set_label_2() called')

    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    container_item_0 = [item[0] for item in container_data]

    phantom.set_sensitivity(container=container, sensitivity="amber")

    phantom.set_status(container=container, status="Open")

    phantom.pin(container=container, data=container_item_0, message="chris wuz here", pin_type="card", pin_style="red", name=None)

    phantom.set_label(container=container, label="sample")
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
        'source_data_identifier': "",
        'cef_name': "deviceHostname",
        'cef_value': 44444,
        'cef_dictionary': "",
        'contains': "",
    })

    phantom.act("add artifact", parameters=parameters, assets=['myph3'], name="add_artifact_1")

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