"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'my_geo' block
    my_geo(container=container)

    return

def my_geo(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("my_geo() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.id"])

    parameters = []

    # build parameters list for 'my_geo' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "ip": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("geolocate ip", parameters=parameters, name="my_geo", assets=["maxmind"], callback=my_geo_callback)

    return


def my_geo_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("my_geo_callback() called")

    
    debug_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    decision_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("debug_1() called")

    my_geo_result_data = phantom.collect2(container=container, datapath=["my_geo:action_result.data.*.country_iso_code","my_geo:action_result.data.*.country_name","my_geo:action_result.parameter.context.artifact_id"], action_results=results)
    my_lookup_ip_result_data = phantom.collect2(container=container, datapath=["my_lookup_ip:action_result.status","my_lookup_ip:action_result.parameter.context.artifact_id"], action_results=results)
    whois_ip_1_result_data = phantom.collect2(container=container, datapath=["whois_ip_1:action_result.status","whois_ip_1:action_result.message","whois_ip_1:action_result.parameter.context.artifact_id"], action_results=results)

    my_geo_result_item_0 = [item[0] for item in my_geo_result_data]
    my_geo_result_item_1 = [item[1] for item in my_geo_result_data]
    my_lookup_ip_result_item_0 = [item[0] for item in my_lookup_ip_result_data]
    whois_ip_1_result_item_0 = [item[0] for item in whois_ip_1_result_data]
    whois_ip_1_result_message = [item[1] for item in whois_ip_1_result_data]

    parameters = []

    parameters.append({
        "input_1": my_geo_result_item_0,
        "input_2": my_geo_result_item_1,
        "input_3": my_lookup_ip_result_item_0,
        "input_4": whois_ip_1_result_item_0,
        "input_5": whois_ip_1_result_message,
        "input_6": None,
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


def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="and",
        conditions=[
            ["my_geo:action_result.data.*.country_name", "!=", "United States"],
            ["my_geo:action_result.data.*.country_name", "!=", "Brazil"],
            ["my_geo:action_result.data.*.country_name", "!=", "Australia"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        prompt_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_1() called")

    # set user and message variables for phantom.prompt call

    user = "Administrator"
    message = """The container {0} with severity {1} has IPs outside our countries.\n\nIP: {2} is from {3}"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "container:severity",
        "my_geo:action_result.parameter.ip",
        "my_geo:action_result.data.*.country_name"
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=1, name="prompt_1", parameters=parameters, response_types=response_types, callback=decision_2)

    return


def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_1:action_result.summary.responses.0", "!=", "No"]
        ],
        case_sensitive=False)

    # call connected blocks if condition 1 matched
    if found_match_1:
        set_severity_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def set_severity_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_severity_2() called")

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