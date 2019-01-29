"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'whois_ip_1' block
    whois_ip_1(container=container)

    # call 'whois_domain_1' block
    whois_domain_1(container=container)

    # call 'format_3' block
    format_3(container=container)

    return

def whois_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('whois_ip_1() called')

    # collect data for 'whois_ip_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'whois_ip_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("whois ip", parameters=parameters, assets=['whois'], callback=format_1, name="whois_ip_1")

    return

def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_1() called')
    
    template = """{0}
{1}
{2}"""

    # parameter list for template variable replacement
    parameters = [
        "whois_ip_1:action_result.data.*.nets.*.city",
        "whois_ip_1:action_result.data.*.nets.*.cidr",
        "whois_ip_1:action_result.message",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    join_send_email_1(container=container)

    return

def whois_domain_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('whois_domain_1() called')

    # collect data for 'whois_domain_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceDnsDomain', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'whois_domain_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'domain': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("whois domain", parameters=parameters, assets=['whois'], callback=set_label_1, name="whois_domain_1")

    return

def set_label_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('set_label_1() called')

    phantom.set_label(container, "events")
    join_send_email_1(container=container)

    return

def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('send_email_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    phantom.act("send email", parameters=parameters, callback=format_2, name="send_email_1")

    return

def join_send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_send_email_1() called')

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'whois_domain_1', 'whois_ip_1' ]):
        
        # call connected block "send_email_1"
        send_email_1(container=container, handle=handle)
    
    return

def format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_2() called')
    
    template = """{0}{1}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.cn2Label",
        "artifact:*.cef.cs1Label",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_2")

    decision_1(container=container)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["format_2:formatted_data", "==", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        return

    return

def format_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_3() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "container:hash",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_3")

    join_send_email_1(container=container)

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