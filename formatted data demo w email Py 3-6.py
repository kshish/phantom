"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'cf_community_list_merge_1' block
    cf_community_list_merge_1(container=container)

    # call 'provide_email_addr' block
    provide_email_addr(container=container)

    return

def cf_community_list_merge_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_list_merge_1() called')
    
    container_data_0 = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.cef.sourceAddress', 'artifact:*.id'])

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
    phantom.custom_function(custom_function='community/list_merge', parameters=parameters, name='cf_community_list_merge_1', callback=join_geolocate_ip_1)

    return

def provide_email_addr(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('provide_email_addr() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """Please enter your email address"""

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "message",
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="provide_email_addr", response_types=response_types, callback=join_geolocate_ip_1)

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

    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], callback=geolocate_ip_1_callback, name="geolocate_ip_1")

    return

def geolocate_ip_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('geolocate_ip_1_callback() called')
    
    send_email_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    format_a_list(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def join_geolocate_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_geolocate_ip_1() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['provide_email_addr'], custom_function_names=['cf_community_list_merge_1']):
        
        # call connected block "geolocate_ip_1"
        geolocate_ip_1(container=container, handle=handle)
    
    return

def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_email_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_email_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['provide_email_addr:action_result.parameter.message', 'provide_email_addr:action_result.parameter.context.artifact_id'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['geolocate_ip_1:action_result.data.*.country_name', 'geolocate_ip_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'send_email_1' call
    for results_item_1 in results_data_1:
        for results_item_2 in results_data_2:
            if results_item_1[0] and results_item_2[0]:
                parameters.append({
                    'from': "",
                    'to': results_item_1[0],
                    'cc': "",
                    'bcc': "",
                    'subject': "straight from geo locate unformatted",
                    'body': results_item_2[0],
                    'attachments': "",
                    'headers': "",
                    # context (artifact id) is added to associate results with the artifact
                    'context': {'artifact_id': results_item_1[1]},
                })

    phantom.act(action="send email", parameters=parameters, assets=['smtp'], name="send_email_1", parent_action=action)

    return

def format_a_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_a_list() called')
    
    template = """%%
ip {0} is from {1}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "geolocate_ip_1:action_result.parameter.ip",
        "geolocate_ip_1:action_result.data.*.country_name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_a_list")

    send_email_2(container=container)
    send_email_3(container=container)

    return

def send_email_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_email_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_email_2' call
    results_data_1 = phantom.collect2(container=container, datapath=['provide_email_addr:action_result.parameter.message', 'provide_email_addr:action_result.parameter.context.artifact_id'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='format_a_list__as_list')

    parameters = []
    
    # build parameters list for 'send_email_2' call
    for formatted_part_1 in formatted_data_1:
        for results_item_1 in results_data_1:
            if results_item_1[0]:
                parameters.append({
                    'from': "",
                    'to': results_item_1[0],
                    'cc': "",
                    'bcc': "",
                    'subject': "email body using formatted data *",
                    'body': formatted_part_1,
                    'attachments': "",
                    'headers': "",
                    # context (artifact id) is added to associate results with the artifact
                    'context': {'artifact_id': results_item_1[1]},
                })

    phantom.act(action="send email", parameters=parameters, assets=['smtp'], name="send_email_2")

    return

def send_email_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_email_3() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_email_3' call
    results_data_1 = phantom.collect2(container=container, datapath=['provide_email_addr:action_result.parameter.message', 'provide_email_addr:action_result.parameter.context.artifact_id'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='format_a_list')

    parameters = []
    
    # build parameters list for 'send_email_3' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'from': "",
                'to': results_item_1[0],
                'cc': "",
                'bcc': "",
                'subject': "email body using formatted data (no *)",
                'body': formatted_data_1,
                'attachments': "",
                'headers': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="send email", parameters=parameters, assets=['smtp'], name="send_email_3")

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