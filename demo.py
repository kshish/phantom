"""
This is my playbook
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

##############################
# Start - Global Code Block

import mymodule

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'my_whois' block
    my_whois(container=container)

    # call 'send_email_1' block
    send_email_1(container=container)

    return

"""
My whois description
"""
def my_whois(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('my_whois() called')

    # collect data for 'my_whois' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.dst', 'artifact:*.id'])

    parameters = []
    # my comment
    
    # build parameters list for 'my_whois' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("whois ip", parameters=parameters, assets=['whois'], callback=geolocate_ip_1, name="my_whois")

    return

def geolocate_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('geolocate_ip_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'geolocate_ip_1' call
    inputs_data_1 = phantom.collect2(container=container, datapath=['my_whois:artifact:*.cef.deviceAddress', 'my_whois:artifact:*.id'], action_results=results)

    parameters = []
    
    # build parameters list for 'geolocate_ip_1' call
    for inputs_item_1 in inputs_data_1:
        if inputs_item_1[0]:
            parameters.append({
                'ip': inputs_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': inputs_item_1[1]},
            })

    phantom.act("geolocate ip", parameters=parameters, assets=['maxmind'], callback=join_block_ip_1, name="geolocate_ip_1", parent_action=action)

    return

def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('send_email_1() called')

    parameters = []

    phantom.act("send email", parameters=parameters, callback=join_block_ip_1, name="send_email_1")

    return

def block_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('block_ip_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'block_ip_1' call

    parameters = []
    
    # build parameters list for 'block_ip_1' call
    parameters.append({
        'ip_hostname': "",
        'remote_ip': "",
        'remote_port': "",
        'protocol': "",
        'direction': "",
        'comment': "",
    })

    phantom.act("block ip", parameters=parameters, assets=['phantom local'], callback=decision_1, name="block_ip_1", parent_action=action)

    return

def join_block_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_block_ip_1() called')

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'send_email_1', 'geolocate_ip_1' ]):
        
        # call connected block "block_ip_1"
        block_ip_1(container=container, handle=handle)
    
    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["block_ip_1:action_result.status", "==", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        format_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_1() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

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