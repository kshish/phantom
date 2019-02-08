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
def my_geo_locate(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
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

    phantom.act("geolocate ip", parameters=parameters, assets=['maxmind'], callback=Prompt_Message, name="my_geo_locate")

    return

def Prompt_block_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Prompt_block_IP() called')
    
    # set user and message variables for phantom.prompt call
    user = "Administrator"
    message = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "Prompt_Message:formatted_data",
    ]

    # response options
    options = {
        "type": "list",
        "choices": [
            "Yes",
            "No",
        ]
    }

    phantom.prompt(container=container, user=user, message=message, respond_in_mins=30, name="Prompt_block_IP", parameters=parameters, options=options, callback=decision_2)

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
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

def block_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
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
                'direction': "asdf",
                'protocol': "asdf",
                'remote_port': "",
                'ip_hostname': inputs_item_1[0],
                'remote_ip': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': inputs_item_1[1]},
            })

    phantom.act("block ip", parameters=parameters, assets=['my local phantom'], name="block_ip_1")

    return

def Prompt_Message(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Prompt_Message() called')
    
    template = """The following is the IP/Country geolocation information we looked up:

%%
IP: {2}
City: {0}
Country: {1}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "my_geo_locate:action_result.data.0.city_name",
        "my_geo_locate:action_result.data.0.country_name",
        "my_geo_locate:action_result.parameter.ip",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Prompt_Message")

    Prompt_block_IP(container=container)

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