"""
This will end up in comments of python script
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'my_geolocate' block
    my_geolocate(container=container)

    return

def my_geolocate(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
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
    phantom.debug(parameters)
    phantom.debug('chris wuz here')
    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], callback=send_country_name_email, name="my_geolocate")

    return

def send_country_name_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_country_name_email() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    name_value = container.get('name', None)

    # collect data for 'send_country_name_email' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.toEmail', 'artifact:*.id'])
    results_data_1 = phantom.collect2(container=container, datapath=['my_geolocate:action_result.data.*.country_name', 'my_geolocate:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'send_country_name_email' call
    for container_item in container_data:
        for results_item_1 in results_data_1:
            if container_item[0] and results_item_1[0]:
                parameters.append({
                    'from': "donotreply@splunk.com",
                    'to': container_item[0],
                    'cc': "",
                    'bcc': "",
                    'subject': name_value,
                    'body': results_item_1[0],
                    'attachments': "",
                    'headers': "",
                    # context (artifact id) is added to associate results with the artifact
                    'context': {'artifact_id': container_item[1]},
                })

    phantom.act(action="send email", parameters=parameters, assets=['smtp'], callback=decision_1, name="send_country_name_email", parent_action=action)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["send_country_name_email:action_result.status", "==", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        return

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