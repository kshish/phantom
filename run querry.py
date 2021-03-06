"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'format_SPL' block
    format_my_SPL(container=container)
    phantom.debug('chris wuz here')
    return

def run_query_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_query_1() called')

    # collect data for 'run_query_1' call
    formatted_data_1 = phantom.get_format_data(name='format_my_SPL')

    parameters = []
    
    # build parameters list for 'run_query_1' call
    parameters.append({
        'query': formatted_data_1,
        'display': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['esa100'], callback=format_prompt_message, name="run_query_1")

    return

def format_my_SPL(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_SPL() called')
    
    template = """| savedsearch myhosts server={0}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destination",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_SPL")
    phantom.debug(container)
    run_query_1(container=container)

    return

def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_1() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """The host {1} communicated with 

{0}

Do you want to update the notable event with in progress?"""

    # parameter list for template variable replacement
    parameters = [
        "format_prompt_message:formatted_data",
        "artifact:*.cef.destination",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_1", parameters=parameters, response_types=response_types, callback=decision_1)

    return

def update_event_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_event_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'update_event_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.event_id', 'artifact:*.id'])
    formatted_data_1 = phantom.get_format_data(name='format_2')

    parameters = []
    
    # build parameters list for 'update_event_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'owner': "",
                'status': "in progress",
                'comment': formatted_data_1,
                'urgency': "high",
                'event_ids': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="update event", parameters=parameters, assets=['esa100'], name="update_event_1")

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["prompt_1:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        format_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_2() called')
    
    template = """click here to see the container in Phantom {0}"""

    # parameter list for template variable replacement
    parameters = [
        "container:url",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_2")

    update_event_1(container=container)

    return

def format_prompt_message(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_prompt_message() called')
    
    template = """%%
dest is {0} count is {1} with priority {2}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "run_query_1:action_result.data.*.peer",
        "run_query_1:action_result.data.*.count",
        "run_query_1:action_result.data.*.priority",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_prompt_message")

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