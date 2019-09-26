"""
This will show up in the python comments
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'geolocate_sourceAddress' block
    geolocate_sourceAddress(container=container)

    return

"""
geolocates sourceAddress on containers
"""
def geolocate_sourceAddress(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('geolocate_sourceAddress() called')

    # collect data for 'geolocate_sourceAddress' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'geolocate_sourceAddress' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("geolocate ip", parameters=parameters, assets=['maxmind'], callback=decide_what_country_ip_is_in, name="geolocate_sourceAddress")

    return

def decide_what_country_ip_is_in(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decide_what_country_ip_is_in() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["geolocate_sourceAddress:action_result.data.*.country_name", "==", "United States"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        return

    # call connected blocks for 'else' condition 2
    filter_1(action=action, success=success, container=container, results=results, handle=handle)

    return

def ask_analyst_to_set_severity_to_high(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('ask_analyst_to_set_severity_to_high() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "format_msg_for_analyst:formatted_data.*",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=2, name="ask_analyst_to_set_severity_to_high", parameters=parameters, response_types=response_types, callback=decision_2)

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["ask_analyst_to_set_severity_to_high:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        playbook_chris_child_pb_do_bunch_of_stuff_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["geolocate_sourceAddress:action_result.data.*.country_name", "!=", ""],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_msg_for_analyst(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def format_msg_for_analyst(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_msg_for_analyst() called')
    
    template = """This container {2}, sourceAddress are from: 

%% 
City: {0}
Country: {1}
%%

IP(s) outside of the U.S. Do you want to set severity to high?"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_1:geolocate_sourceAddress:action_result.data.*.city_name",
        "filtered-data:filter_1:condition_1:geolocate_sourceAddress:action_result.data.*.country_name",
        "container:name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_msg_for_analyst")

    ask_analyst_to_set_severity_to_high(container=container)

    return

def playbook_chris_child_pb_do_bunch_of_stuff_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('playbook_chris_child_pb_do_bunch_of_stuff_1() called')
    
    # call playbook "chris/child pb do bunch of stuff", returns the playbook_run_id
    playbook_run_id = phantom.playbook("chris/child pb do bunch of stuff", container=container, name="playbook_chris_child_pb_do_bunch_of_stuff_1", callback=decision_3)

    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_3() called')
    
    severity_param = container.get('severity', None)

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            [severity_param, "==", "High"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        set_label_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def set_label_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('set_label_1() called')

    phantom.set_label(container=container, label="events")

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