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

    phantom.act("geolocate ip", parameters=parameters, assets=['maxmind'], callback=join_send_email_1, name="my_geolocate")

    return

def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('send_email_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_email_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['my_geolocate:action_result.data.*.country_name', 'my_geolocate:action_result.parameter.context.artifact_id'], action_results=results)
    inputs_data_1 = phantom.collect2(container=container, datapath=['my_geolocate:artifact:*.cef.sourceAddress', 'my_geolocate:artifact:*.id'], action_results=results)

    parameters = []
    
    # build parameters list for 'send_email_1' call
    for results_item_1 in results_data_1:
        for inputs_item_1 in inputs_data_1:
            if results_item_1[0]:
                parameters.append({
                    'body': results_item_1[0],
                    'from': "churyn@splunk.com",
                    'attachments': "",
                    'to': "churyn@splunk.com",
                    'cc': "",
                    'bcc': "",
                    'headers': "",
                    'subject': inputs_item_1[0],
                    # context (artifact id) is added to associate results with the artifact
                    'context': {'artifact_id': results_item_1[1]},
                })

    phantom.act("send email", parameters=parameters, assets=['smtp'], name="send_email_1", parent_action=action)

    return

def join_send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_send_email_1() called')

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'my_geolocate', 'my_lookup' ]):
        
        # call connected block "send_email_1"
        send_email_1(container=container, handle=handle)
    
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
    phantom.debug("container info:")
    phantom.debug(container)
    phantom.act("lookup ip", parameters=parameters, assets=['google_dns'], callback=join_send_email_1, name="my_lookup")

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