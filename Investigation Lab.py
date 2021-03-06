"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'domain_reputation_1' block
    domain_reputation_1(container=container)

    # call 'file_reputation_1' block
    file_reputation_1(container=container)

    # call 'filter_1' block
    filter_1(container=container)

    return

def geolocate_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('geolocate_ip_1() called')

    # collect data for 'geolocate_ip_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'geolocate_ip_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("geolocate ip", parameters=parameters, assets=['maxmind'], callback=join_decision_2, name="geolocate_ip_1")

    return

def domain_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('domain_reputation_1() called')

    # collect data for 'domain_reputation_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceDnsDomain', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'domain_reputation_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'domain': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("domain reputation", parameters=parameters, assets=['virus total'], callback=join_decision_2, name="domain_reputation_1")

    return

def file_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('file_reputation_1() called')

    # collect data for 'file_reputation_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.fileHash', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'file_reputation_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'hash': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("file reputation", parameters=parameters, assets=['virus total'], callback=join_decision_2, name="file_reputation_1")

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_1:action_result.summary.positives", ">", 1000],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        join_add_list_3(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2
    format_1(action=action, success=success, container=container, results=results, handle=handle)

    return

def Notify_IT(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Notify_IT() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """A bad file has been detected, mmmmkay. Notify IT team?
Country: {0}
Message: {1} {2}
Alexa rank: {3}
__________"""

    # parameter list for template variable replacement
    parameters = [
        "geolocate_ip_1:action_result.data.*.country_name",
        "file_reputation_1:action_result.message",
        "file_reputation_1:action_result.data.*.response_code",
        "domain_reputation_1:action_result.data.*.Alexa rank",
    ]

    # response options
    options = {
        "type": "list",
        "choices": [
            "Yes",
            "No",
        ]
    }

    phantom.prompt(container=container, user=user, message=message, respond_in_mins=30, name="Notify_IT", parameters=parameters, options=options, callback=decision_3)

    return

def Promote_to_case(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Promote_to_case() called')
    
    # call playbook "Chris/Case Promotion Lab get action results", returns the playbook_run_id
    playbook_run_id = phantom.playbook("Chris/Case Promotion Lab get action results", container=container)

    return

def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_1() called')
    
    template = """Threat level found to be low
{0}
{1}
{2}"""

    # parameter list for template variable replacement
    parameters = [
        "domain_reputation_1:action_result.message",
        "domain_reputation_1:action_result.data.*.Alexa rank",
        "domain_reputation_1:action_result.status",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    pin_1(container=container)

    return

def pin_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('pin_1() called')

    formatted_data_1 = phantom.get_format_data(name='format_1')

    phantom.pin(container=container, message="Resolved by Chris wuz here", data=formatted_data_1, pin_type="", pin_style="")
    add_comment_2(container=container)

    return

def add_comment_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('add_comment_2() called')

    results_data_1 = phantom.collect2(container=container, datapath=['geolocate_ip_1:action_result.message'], action_results=results)

    results_item_1_0 = [item[0] for item in results_data_1]

    phantom.comment(container=container, comment=results_item_1_0)

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["geolocate_ip_1:action_result.data.*.country_name", "in", "custom_list:Banned Countries"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        join_add_list_3(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2
    decision_1(action=action, success=success, container=container, results=results, handle=handle)

    return

def join_decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_decision_2() called')

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'geolocate_ip_1', 'file_reputation_1', 'domain_reputation_1' ]):
        
        # call connected block "decision_2"
        decision_2(container=container, handle=handle)
    
    return

def add_list_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('add_list_3() called')

    inputs_data_1 = phantom.collect2(container=container, datapath=['file_reputation_1:artifact:*.cef.fileHash'], action_results=results)

    inputs_item_1_0 = [item[0] for item in inputs_data_1]

    phantom.add_list("Bad file hashes", inputs_item_1_0)
    Notify_IT(container=container)

    return

def join_add_list_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_add_list_3() called')

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'geolocate_ip_1', 'file_reputation_1', 'domain_reputation_1' ]):
        
        # call connected block "add_list_3"
        add_list_3(container=container, handle=handle)
    
    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Notify_IT:action_result.summary.response", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        Promote_to_case(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceAddress", "!=", None],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        geolocate_ip_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

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