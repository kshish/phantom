"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'test_no_wildcard' block
    test_no_wildcard(container=container)

    # call 'test_with_wildcards_surounding' block
    test_with_wildcards_surounding(container=container)

    # call 'just_wildcard' block
    just_wildcard(container=container)

    return

def test_no_wildcard(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('test_no_wildcard() called')

    # collect data for 'test_no_wildcard' call

    parameters = []
    
    # build parameters list for 'test_no_wildcard' call
    parameters.append({
        'ip': "artifact:test.cef.destinationAddress",
    })

    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], callback=join_prompt_1, name="test_no_wildcard")

    return

def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_1() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """Specific path without wildcard:
artifact:test.cef.destinationAddress
ip {0}. country {1}
----
Wildcards surrounding word in datapath:
artifact:*test*.cef.destinationAddress
ip {2}. country {3}
----
Just wildcard (default)
artifact:*.cef.destinationAddress
ip {4}. country {5}"""

    # parameter list for template variable replacement
    parameters = [
        "test_no_wildcard:action_result.parameter.ip",
        "test_no_wildcard:action_result.data.*.country_name",
        "test_with_wildcards_surounding:action_result.parameter.ip",
        "test_with_wildcards_surounding:action_result.data.*.country_name",
        "just_wildcard:action_result.parameter.ip",
        "just_wildcard:action_result.data.*.country_name",
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

def join_prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_prompt_1() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['test_no_wildcard', 'test_with_wildcards_surounding', 'just_wildcard']):
        
        # call connected block "prompt_1"
        prompt_1(container=container, handle=handle)
    
    return

def test_with_wildcards_surounding(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('test_with_wildcards_surounding() called')

    # collect data for 'test_with_wildcards_surounding' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*test*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'test_with_wildcards_surounding' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], callback=join_prompt_1, name="test_with_wildcards_surounding")

    return

def just_wildcard(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('just_wildcard() called')

    # collect data for 'just_wildcard' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'just_wildcard' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], callback=join_prompt_1, name="just_wildcard")

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return