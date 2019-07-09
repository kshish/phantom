"""
This will be a comment in the python code
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'my_geolocate' block
    my_geolocate(container=container)

    # call 'my_lookup' block
    my_lookup(container=container)

    return

"""
this goes out to a service and looks up the public ip information
"""
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

    phantom.act("geolocate ip", parameters=parameters, assets=['maxmind'], callback=join_Ask_analyst_to_block_ip, name="my_geolocate")

    return

def my_lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('my_lookup() called')

    # collect data for 'my_lookup' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'my_lookup' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("lookup ip", parameters=parameters, assets=['google_dns'], callback=join_Ask_analyst_to_block_ip, name="my_lookup")

    return

def Ask_analyst_to_block_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Ask_analyst_to_block_ip() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """Geolocate of ip  {0} address is in {1} country.
Do you want to block ip?"""

    # parameter list for template variable replacement
    parameters = [
        "my_geolocate:action_result.parameter.ip",
        "my_geolocate:action_result.data.*.country_name",
    ]

    # response options
    options = {
        "type": "list",
        "choices": [
            "Yes",
            "No",
        ]
    }

    phantom.prompt(container=container, user=user, message=message, respond_in_mins=1, name="Ask_analyst_to_block_ip", parameters=parameters, options=options, callback=decision_4)

    return

def join_Ask_analyst_to_block_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_Ask_analyst_to_block_ip() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_Ask_analyst_to_block_ip_called'):
        return

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'my_geolocate' ]):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_Ask_analyst_to_block_ip_called', value='Ask_analyst_to_block_ip')
        
        # call connected block "Ask_analyst_to_block_ip"
        Ask_analyst_to_block_ip(container=container, handle=handle)
    
    return

def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_4() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Ask_analyst_to_block_ip:action_result.summary.response", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        set_severity_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def set_severity_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('set_severity_1() called')

    phantom.set_severity(container, "high")

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