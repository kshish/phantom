"""
This playbook will blah blah blah
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'my_geo_locate' block
    my_geo_locate(container=container)
    phantom.debug("zed wuz here")
    # call 'whois_ip_1' block

    return

"""
This code retrieves geographic  location information from an ip address
"""
def my_geo_locate(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('my_geo_locate() called')

    # collect data for 'my_geo_locate' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'my_geo_locate' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], callback=filter_1, name="my_geo_locate")

    return

def Prompt_block_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Prompt_block_IP() called')
    
    # set user and message variables for phantom.prompt call
    user = "Administrator"
    message = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "format_2:formatted_data",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="Prompt_block_IP", parameters=parameters, response_types=response_types, callback=decision_2)

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Prompt_block_IP:action_result.summary.response", "==", "Yes"],
        ])
    phantom.debug('results from:')
    phantom.debug(results)
    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        block_ip_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2

    return

def block_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('block_ip_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'block_ip_1' call
    inputs_data_1 = phantom.collect2(container=container, datapath=['my_geo_locate:artifact:*.cef.destinationAddress', 'my_geo_locate:artifact:*.id'], action_results=results)

    parameters = []
    
    # build parameters list for 'block_ip_1' call
    for inputs_item_1 in inputs_data_1:
        if inputs_item_1[0]:
            parameters.append({
                'comment': "",
                'protocol': "asdf",
                'direction': "asdf",
                'remote_ip': "",
                'ip_hostname': inputs_item_1[0],
                'remote_port': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': inputs_item_1[1]},
            })

    phantom.act(action="block ip", parameters=parameters, assets=['myloco'], callback=add_list_1, name="block_ip_1")

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["my_geo_locate:action_result.data.*.country_name", "!=", ""],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def add_list_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_list_1() called')

    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:my_geo_locate:action_result.data.1.country_name'])

    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    phantom.add_list("countries", filtered_results_item_1_0)

    return

def format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_2() called')
    
    template = """The following is the IP/Country geolocation information we looked up:

%%
IP: {0}
City: {1}
Country: {2}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_1:my_geo_locate:action_result.parameter.ip",
        "filtered-data:filter_1:condition_1:my_geo_locate:action_result.data.*.city_name",
        "filtered-data:filter_1:condition_1:my_geo_locate:action_result.data.*.country_name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_2")

    Prompt_block_IP(container=container)

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