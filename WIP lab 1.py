"""
This playbook collects intel on artifacts in container
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'My_Geolocate' block
    My_Geolocate(container=container)

    return

"""
This block will look up geo location of ip.
"""
def My_Geolocate(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('My_Geolocate() called')

    # collect data for 'My_Geolocate' call

    parameters = []
    
    # build parameters list for 'My_Geolocate' call
    parameters.append({
        'ip': "222.222.222.222",
    })

    phantom.act("geolocate ip", parameters=parameters, assets=['maxmind'], callback=Analyst_decide_something, name="My_Geolocate")

    return

def Analyst_decide_something(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Analyst_decide_something() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """The ip is from  {1}, {2}, {0}
The iso code is: {3}"""

    # parameter list for template variable replacement
    parameters = [
        "My_Geolocate:action_result.data.*.country_name",
        "My_Geolocate:action_result.data.*.city_name",
        "My_Geolocate:action_result.data.*.state_name",
        "My_Geolocate:action_result.data.*.state_iso_code",
    ]

    # response options
    options = {
        "type": "list",
        "choices": [
            "Yes",
            "No",
        ]
    }

    phantom.prompt(container=container, user=user, message=message, respond_in_mins=30, name="Analyst_decide_something", parameters=parameters, options=options, callback=decision_3)

    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Analyst_decide_something:action_result.summary.response", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        prompt_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def prompt_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('prompt_2() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """Then answer was yes and  {0}"""

    # parameter list for template variable replacement
    parameters = [
        "Analyst_decide_something:action_result.summary.response",
    ]

    phantom.prompt(container=container, user=user, message=message, respond_in_mins=30, name="prompt_2", parameters=parameters)

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