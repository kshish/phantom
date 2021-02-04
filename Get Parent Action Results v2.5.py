"""
This playbook gets the parent playbook action results and checks to see if there were any action failures and sends an email if failures are found. You should call this playbook in End or on_finish block of your playbook for the best results. This playbook will only gather the information on the 'parent' playbook it is attached to.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'get_playbook_id' block
    get_playbook_id(container=container)

    return

def get_playbook_action_runs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('get_playbook_action_runs() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_playbook_action_runs' call
    formatted_data_1 = phantom.get_format_data(name='playbook_action_run_url')

    parameters = []
    
    # build parameters list for 'get_playbook_action_runs' call
    parameters.append({
        'headers': "",
        'location': formatted_data_1,
        'verify_certificate': False,
    })

    phantom.act("get data", parameters=parameters, assets=['phantom_rest'], callback=check_action_runs, name="get_playbook_action_runs")

    return

def playbook_action_run_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('playbook_action_run_url() called')
    
    template = """action_run?_filter_playbook_run={0}&page_size=0"""

    # parameter list for template variable replacement
    parameters = [
        "get_playbook_id:custom_function:parent_pb_run_id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="playbook_action_run_url")

    get_playbook_action_runs(container=container)

    return

def get_playbook_id(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('get_playbook_id() called')
    input_parameter_0 = ""

    get_playbook_id__parent_pb_run_id = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    get_playbook_id__parent_pb_run_id = int(phantom.get_playbook_info()[0]['parent_playbook_run_id'])
    phantom.debug('parent_playbook_id: {}'.format(get_playbook_id__parent_pb_run_id))
    
    # Used for Testing
    # get_playbook_id__parent_pb_run_id = 2479
    # phantom.debug('Testing parent_playbook_id: {}'.format(get_playbook_id__parent_pb_run_id))

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='get_playbook_id:parent_pb_run_id', value=json.dumps(get_playbook_id__parent_pb_run_id))
    check_parent_playbook_id(container=container)

    return

def check_parent_playbook_id(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('check_parent_playbook_id() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["get_playbook_id:custom_function:parent_pb_run_id", "!=", 0],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        playbook_run_data_url(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2

    return

def get_app_run_data(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('get_app_run_data() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_app_run_data' call
    formatted_data_1 = phantom.get_format_data(name='action_block_app_runs_url__as_list')

    parameters = []
    
    # build parameters list for 'get_app_run_data' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'headers': "",
            'location': formatted_part_1,
            'verify_certificate': False,
        })

    phantom.act("get data", parameters=parameters, assets=['phantom_rest'], callback=subject_body, name="get_app_run_data")

    return

def get_parent_playbook_data(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('get_parent_playbook_data() called')

    # collect data for 'get_parent_playbook_data' call
    formatted_data_1 = phantom.get_format_data(name='playbook_run_data_url')

    parameters = []
    
    # build parameters list for 'get_parent_playbook_data' call
    parameters.append({
        'headers': "",
        'location': formatted_data_1,
        'verify_certificate': False,
    })

    phantom.act("get data", parameters=parameters, assets=['phantom_rest'], callback=playbook_message_format, name="get_parent_playbook_data")

    return

def playbook_run_data_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('playbook_run_data_url() called')
    
    template = """playbook_run/{0}/?pretty"""

    # parameter list for template variable replacement
    parameters = [
        "get_playbook_id:custom_function:parent_pb_run_id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="playbook_run_data_url")

    get_parent_playbook_data(container=container)

    return

"""
Sends Failure email to customer for troubleshooting
"""
def send_failed_playbook_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('send_failed_playbook_email() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    playbook_email_body__body_format = json.loads(phantom.get_run_data(key='playbook_email_body:body_format'))
    # collect data for 'send_failed_playbook_email' call
    formatted_data_1 = phantom.get_format_data(name='subject_body')

    parameters = []
    
    # build parameters list for 'send_failed_playbook_email' call
    parameters.append({
        'body': playbook_email_body__body_format,
        'from': "phantom@phantom.us",
        'attachments': "",
        'to': "phantom@phantom.us",
        'cc': "",
        'bcc': "",
        'headers': "",
        'subject': formatted_data_1,
    })

    phantom.act("send email", parameters=parameters, assets=['smtp'], name="send_failed_playbook_email")

    return

def subject_body(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('subject_body() called')
    
    template = """Failed actions for playbook: {0}"""

    # parameter list for template variable replacement
    parameters = [
        "get_parent_playbook_data:action_result.data.*.response_body._pretty_playbook",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="subject_body")

    playbook_check(container=container)

    return

"""
Creates email body format of failed parent playbook actions
"""
def playbook_email_body(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('playbook_email_body() called')
    playbook_message_format__message = json.loads(phantom.get_run_data(key='playbook_message_format:message'))
    url_value = container.get('url', None)
    results_data_1 = phantom.collect2(container=container, datapath=['get_parent_playbook_data:action_result.data.*.response_body.id', 'get_parent_playbook_data:action_result.data.*.response_body._pretty_playbook', 'get_parent_playbook_data:action_result.data.*.response_body.status'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['get_playbook_action_runs:action_result.data.*.response_body.data.*.id', 'get_playbook_action_runs:action_result.data.*.response_body.data.*.name', 'get_playbook_action_runs:action_result.data.*.response_body.data.*.action', 'get_playbook_action_runs:action_result.data.*.response_body.data.*.status', 'get_playbook_action_runs:action_result.data.*.response_body.data.*.message'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['get_app_run_data:action_result.data.*.response_body.data.*.action_run', 'get_app_run_data:action_result.data.*.response_body.data.*.app_name', 'get_app_run_data:action_result.data.*.response_body.data.*.action', 'get_app_run_data:action_result.data.*.response_body.data.*.status', 'get_app_run_data:action_result.data.*.response_body.data.*.result_data.*.message'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_1_1 = [item[1] for item in results_data_1]
    results_item_1_2 = [item[2] for item in results_data_1]
    results_item_2_0 = [item[0] for item in results_data_2]
    results_item_2_1 = [item[1] for item in results_data_2]
    results_item_2_2 = [item[2] for item in results_data_2]
    results_item_2_3 = [item[3] for item in results_data_2]
    results_item_2_4 = [item[4] for item in results_data_2]
    results_item_3_0 = [item[0] for item in results_data_3]
    results_item_3_1 = [item[1] for item in results_data_3]
    results_item_3_2 = [item[2] for item in results_data_3]
    results_item_3_3 = [item[3] for item in results_data_3]
    results_item_3_4 = [item[4] for item in results_data_3]

    playbook_email_body__body_format = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    #phantom.debug('Display Data:')
    #phantom.debug(results_data_2)
    phantom.debug(results_data_3[0][0])
    #phantom.debug(playbook_message_format__message)
    #phantom.debug('End Display Data:')
    
    # Format email body
    # Sets default playbook message if failed but no value returned
    if not playbook_message_format__message:
        playbook_message_format__message = "<strong><span style='color: #ff0000;'> Critical Playbook ERROR Review Playbook Debug Log </span></strong>"
    
    color = "#000000" 
    
    # Sets the color to red from default black if the status failed
    if results_item_1_2[0] == 'failed': 
        color = "#ff0000"
    html_template = "<html><head><body>"
    html_template += "<h2>splunk <span style='color: #808080;'>&gt;phantom </span> is reporting a Playbook or Action Failure! </h2>"
    html_template += "<hr />"
    html_template += "<div><h3><span style='color: #ff0000;'> Error Report for Playbook: </span><strong> {0} </strong></h3></div>".format(results_item_1_1[0])
    html_template += "<ul><li>Reported from: {}</li>".format(url_value)
    html_template += "<li> Reported Playbook status: <strong><span style='color: {0};font-weight:bold'> {1} </span></strong></li>".format(color,results_item_1_2[0])
    html_template += "<li> Playbook Run Id: <strong> {0} </strong></li></ul>".format(results_item_1_0[0])
    html_template += "<p><span style='color: {0};font-weight:bold'> Message: {1} </span></p>".format(color,playbook_message_format__message)
    html_template += "<hr />"    # Playbook runs separaters 
    
    # Format list of action_run?_filter_playbook_run={0}&page_size=0 items 
    error_size = 0
    
    for results_item_2 in results_data_2:
        color = "#000000" 
        if results_item_2[0]: # Provides a limit for SMTP body messages
            # Sets the color to red from default black if the status failed
            if results_item_2[3] == 'failed': 
                color = "#ff0000"
            html_template += "<p><strong> Action Block </strong><br /></p>"
            html_template += "<p>Name: {0} | Action: {1} <br />".format(results_item_2[1],results_item_2[2])
            html_template += "Status: <span style='color: {0};font-weight:bold'> {1} </span><br />".format(color,results_item_2[3])
            html_template += "Status Message: {0} <br /></span></p>".format(results_item_2[4])
        
            # Format list of action_run/{id}/app_runs REST endpoint
            html_template += "<p><strong> Application Runs: </strong></p>"
            for results_item_3 in results_data_3:
                if results_item_2[0] == results_item_3[0]:
                    color = "#000000"
                    # Sets the color to red from default black if the status failed
                    if results_item_3[3] == 'failed':
                        color = "#ff0000"
                    
                    html_template += "<ul><p>App Name: {0} | Action: {1} <br />".format(results_item_3[1],results_item_3[2])
                    html_template += "Status: <span style='color: {0};font-weight:bold'> {1} </span><br />".format(color,results_item_3[3])
                    html_template += "Status Message: {0} <br /></p></ul>".format(results_item_3[4])
                    
                elif not results_data_3[0]: # Checks to see if no applictions runs were completed
                    html_template +=  "<strong><span style='color: #ff0000;font-weight:bold'> No application runs were executed </span><br />"
        
        elif not results_item_2[0]: # Checks to see if no actions were executed
            html_template +=  "<span style='color: #ff0000;font-weight:bold'> No actions were executed </span><br />"

    html_template += "<hr />"   # Application runs separaters 
    
    # Footer Insertion
    html_template += "<p style='text-align: right;'><strong> Sent by splunk</strong><span style='color: #808080;'>&gt;phantom </span></p></body></html>"
    
    # Debug the email body
    playbook_email_body__body_format = html_template
    
    #phantom.debug(html_template)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='playbook_email_body:body_format', value=json.dumps(playbook_email_body__body_format))
    send_failed_playbook_email(container=container)

    return

def join_playbook_email_body(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_playbook_email_body() called')

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'get_app_run_data', 'get_playbook_action_runs' ]):
        
        # call connected block "playbook_email_body"
        playbook_email_body(container=container, handle=handle)
    
    return

def check_action_runs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('check_action_runs() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["get_playbook_action_runs:action_result.data.*.response_body.count", ">", 0],
            ["get_parent_playbook_data:action_result.data.*.response_body.status", "!=", "success"],
        ],
        logical_operator='or')

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        action_block_app_runs_url(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2
    join_playbook_email_body(action=action, success=success, container=container, results=results, handle=handle)

    return

"""
Format and displays the playbook error message format
"""
def playbook_message_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('playbook_message_format() called')
    results_data_1 = phantom.collect2(container=container, datapath=['get_parent_playbook_data:action_result.data.*.response_body.message'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]

    playbook_message_format__message = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    # get playbook error message data     
    playbook_message_format__message = json.loads(results_item_1_0[0])['message']   
    #phantom.debug('Playbook error message: {}'.format(playbook_message_format__message))

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='playbook_message_format:message', value=json.dumps(playbook_message_format__message))
    playbook_action_run_url(container=container)

    return

"""
Checks for action block success
"""
def action_block(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('action_block() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["get_app_run_data:action_result.data.*.response_body.data.*.status", "==", "failed"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        join_playbook_email_body(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["get_playbook_action_runs:action_result.data.*.response_body.data.*.status", "==", "success"],
        ])

    # call connected blocks if condition 2 matched
    if matched_artifacts_2 or matched_results_2:
        return

    # call connected blocks for 'else' condition 3
    join_playbook_email_body(action=action, success=success, container=container, results=results, handle=handle)

    return

"""
Checks playbook successful or not
"""
def playbook_check(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('playbook_check() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["get_parent_playbook_data:action_result.data.*.response_body.status", "==", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        action_block(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2
    join_playbook_email_body(action=action, success=success, container=container, results=results, handle=handle)

    return

def action_block_app_runs_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('action_block_app_runs_url() called')
    
    template = """%%
action_run/{0}/app_runs
%%"""

    # parameter list for template variable replacement
    parameters = [
        "get_playbook_action_runs:action_result.data.*.response_body.data.*.id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="action_block_app_runs_url")

    get_app_run_data(container=container)

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