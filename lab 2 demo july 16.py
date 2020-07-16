"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'geolocate_Source_Address' block
    geolocate_Source_Address(container=container)

    # call 'geolocate_Destination_Address' block
    geolocate_Destination_Address(container=container)

    return

"""
this geolocate uses the source address CEF field from the container 
"""
def geolocate_Source_Address(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('geolocate_Source_Address() called')

    # collect data for 'geolocate_Source_Address' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'geolocate_Source_Address' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("geolocate ip", parameters=parameters, assets=['maxmind'], callback=join_send_email_1, name="geolocate_Source_Address")

    return

def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('send_email_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    name_value = container.get('name', None)

    # collect data for 'send_email_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.fromEmail', 'artifact:*.id'])
    results_data_1 = phantom.collect2(container=container, datapath=['geolocate_Source_Address:action_result.data.*.country_name', 'geolocate_Source_Address:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'send_email_1' call
    for container_item in container_data:
        for results_item_1 in results_data_1:
            if results_item_1[0]:
                parameters.append({
                    'from': container_item[0],
                    'to': "chrishu@splunk.com",
                    'cc': "",
                    'bcc': "",
                    'subject': name_value,
                    'body': results_item_1[0],
                    'attachments': "",
                    'headers': "",
                    # context (artifact id) is added to associate results with the artifact
                    'context': {'artifact_id': container_item[1]},
                })

    phantom.act("send email", parameters=parameters, assets=['smtp'], name="send_email_1", parent_action=action)

    return

def join_send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_send_email_1() called')

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'geolocate_Source_Address', 'geolocate_Destination_Address' ]):
        
        # call connected block "send_email_1"
        send_email_1(container=container, handle=handle)
    
    return

"""
etc.... blah blahh
"""
def geolocate_Destination_Address(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('geolocate_Destination_Address() called')

    # collect data for 'geolocate_Destination_Address' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'geolocate_Destination_Address' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("geolocate ip", parameters=parameters, assets=['maxmind'], callback=join_send_email_1, name="geolocate_Destination_Address")

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