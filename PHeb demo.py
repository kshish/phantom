"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'cf_community_list_merge_1' block
    cf_community_list_merge_1(container=container)

    return

def geolocate_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('geolocate_ip_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'geolocate_ip_1' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_community_list_merge_1:custom_function_result.data.*.item'], action_results=results)

    parameters = []
    
    # build parameters list for 'geolocate_ip_1' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'ip': custom_function_results_item_1[0],
            })

    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], callback=filter_1, name="geolocate_ip_1")

    return

def cf_community_list_merge_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_list_merge_1() called')
    
    container_data_0 = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.cef.myIp', 'artifact:*.id'])

    parameters = []

    container_data_0_0 = [item[0] for item in container_data_0]
    container_data_0_1 = [item[1] for item in container_data_0]

    parameters.append({
        'input_1': container_data_0_0,
        'input_2': container_data_0_1,
        'input_3': None,
        'input_4': None,
        'input_5': None,
        'input_6': None,
        'input_7': None,
        'input_8': None,
        'input_9': None,
        'input_10': None,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/list_merge", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/list_merge', parameters=parameters, name='cf_community_list_merge_1', callback=geolocate_ip_1)

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_1:condition_1:geolocate_ip_1:action_result.data.*.country_name", "!=", "United States"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        format_5(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_1() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """The container {0} with severity {1} 

{2}

Would you like to set high severity?"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "container:severity",
        "format_5:formatted_data",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=1, name="prompt_1", parameters=parameters, response_types=response_types, callback=decision_3)

    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["prompt_1:action_result.summary.responses.0", "!=", "No"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        set_severity_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def set_severity_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_severity_1() called')

    phantom.set_severity(container=container, severity="High")

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["geolocate_ip_1:action_result.data.*.country_name", "!=", ""],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        decision_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def format_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_5() called')
    
    template = """%%
IP: {0} is from {1}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_1:geolocate_ip_1:action_result.parameter.ip",
        "filtered-data:filter_1:condition_1:geolocate_ip_1:action_result.data.*.country_name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_5")

    prompt_1(container=container)

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