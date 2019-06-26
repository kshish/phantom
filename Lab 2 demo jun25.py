"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'My_Geolocate_of_IP' block
    My_Geolocate_of_IP(container=container)

    # call 'My_Whois_IP_lookup' block
    My_Whois_IP_lookup(container=container)

    # call 'url_reputation_1' block
    url_reputation_1(container=container)

    return

def My_Geolocate_of_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('My_Geolocate_of_IP() called')

    # collect data for 'My_Geolocate_of_IP' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'My_Geolocate_of_IP' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("geolocate ip", parameters=parameters, assets=['maxmind'], callback=join_Format_my_msg, name="My_Geolocate_of_IP")

    return

def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('prompt_1() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """{0} 
Would you like to call that child playbook."""

    # parameter list for template variable replacement
    parameters = [
        "Format_my_msg:formatted_data",
    ]

    # response options
    options = {
        "type": "list",
        "choices": [
            "Yes",
            "No",
        ]
    }

    phantom.prompt(container=container, user=user, message=message, respond_in_mins=30, name="prompt_1", parameters=parameters, options=options, callback=decision_2)

    return

def My_Whois_IP_lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('My_Whois_IP_lookup() called')

    # collect data for 'My_Whois_IP_lookup' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'My_Whois_IP_lookup' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("whois ip", parameters=parameters, assets=['whois'], callback=join_Format_my_msg, name="My_Whois_IP_lookup")

    return

def url_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('url_reputation_1() called')

    # collect data for 'url_reputation_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.requestURL', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'url_reputation_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'url': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("url reputation", parameters=parameters, assets=['phishtank'], callback=join_Format_my_msg, name="url_reputation_1")

    return

def Format_my_msg(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Format_my_msg() called')
    
    template = """The container {0} owned by {1} and it is from {2}, {3}, {4}."""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "container:owner",
        "My_Geolocate_of_IP:action_result.data.*.city_name",
        "My_Geolocate_of_IP:action_result.data.*.state_name",
        "My_Geolocate_of_IP:action_result.data.*.country_name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_my_msg")

    prompt_1(container=container)

    return

def join_Format_my_msg(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_Format_my_msg() called')

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'My_Geolocate_of_IP', 'My_Whois_IP_lookup', 'url_reputation_1' ]):
        
        # call connected block "Format_my_msg"
        Format_my_msg(container=container, handle=handle)
    
    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["prompt_1:action_result.summary.response", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        playbook_chris_Child_playbook_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def playbook_chris_Child_playbook_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('playbook_chris_Child_playbook_1() called')
    
    # call playbook "chris/Child playbook", returns the playbook_run_id
    playbook_run_id = phantom.playbook("chris/Child playbook", container=container)

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