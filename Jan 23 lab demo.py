"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')
    phantom.debug("chris wuz here")

    # call 'geolocate_ip_1' block
    geolocate_ip_1(container=container)

    return

def geolocate_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("geolocate_ip_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.id"])

    parameters = []

    # build parameters list for 'geolocate_ip_1' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "ip": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    phantom.debug(parameters)
    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("geolocate ip", parameters=parameters, name="geolocate_ip_1", assets=["maxmind"], callback=geolocate_ip_1_callback)

    return


def geolocate_ip_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("geolocate_ip_1_callback() called")

    
    debug_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    decision_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("debug_1() called")

    name_value = container.get("name", None)
    owner_name_value = container.get("owner_name", None)
    geolocate_ip_1_result_data = phantom.collect2(container=container, datapath=["geolocate_ip_1:action_result.data.*.country_name","geolocate_ip_1:action_result.data.*.latitude","geolocate_ip_1:action_result.data.*.longitude","geolocate_ip_1:action_result.parameter.context.artifact_id"], action_results=results)
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.id"])

    geolocate_ip_1_result_item_0 = [item[0] for item in geolocate_ip_1_result_data]
    geolocate_ip_1_result_item_1 = [item[1] for item in geolocate_ip_1_result_data]
    geolocate_ip_1_result_item_2 = [item[2] for item in geolocate_ip_1_result_data]
    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]

    parameters = []

    parameters.append({
        "input_1": geolocate_ip_1_result_item_0,
        "input_2": geolocate_ip_1_result_item_1,
        "input_3": geolocate_ip_1_result_item_2,
        "input_4": name_value,
        "input_5": owner_name_value,
        "input_6": container_artifact_cef_item_0,
        "input_7": None,
        "input_8": None,
        "input_9": None,
        "input_10": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_1")

    return


def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="or",
        conditions=[
            ["geolocate_ip_1:action_result.data.*.country_name", "==", "United States"],
            ["geolocate_ip_1:action_result.data.*.country_name", "==", "Canada"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        set_severity_to_low(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    prompt_2(action=action, success=success, container=container, results=results, handle=handle)

    return


def set_severity_to_low(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_severity_to_low() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_severity(container=container, severity="low")

    container = phantom.get_container(container.get('id', None))

    return


def prompt_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_2() called")

    # set user and message variables for phantom.prompt call

    user = "Administrator"
    message = """The event {0} with severity {1}\n\nIP(s) are outside of our list\n\nIP: {2} is from {3}\n"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "container:severity",
        "geolocate_ip_1:action_result.parameter.ip",
        "geolocate_ip_1:action_result.data.*.country_name"
    ]

    # responses
    response_types = [
        {
            "prompt": "Would you like to change severity to High?",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=1, name="prompt_2", parameters=parameters, response_types=response_types, callback=decision_3)

    return


def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_3() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_2:action_result.summary.responses.0", "!=", "No"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        set_severity_to_high(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def set_severity_to_high(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_severity_to_high() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_severity(container=container, severity="high")

    container = phantom.get_container(container.get('id', None))

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    summary_json = phantom.get_summary()
    if 'result' in summary_json:
        for action_result in summary_json['result']:
            if 'action_run_id' in action_result:
                action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                phantom.debug(action_results)

    ################################################################################
    ## Custom Code End
    ################################################################################

    return