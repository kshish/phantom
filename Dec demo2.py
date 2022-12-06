"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'list_merge_7' block
    list_merge_7(container=container)

    return

def my_geo(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("my_geo() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    list_merge_7_data = phantom.collect2(container=container, datapath=["list_merge_7:custom_function_result.data.*.item"])

    parameters = []

    # build parameters list for 'my_geo' call
    for list_merge_7_data_item in list_merge_7_data:
        if list_merge_7_data_item[0] is not None:
            parameters.append({
                "ip": list_merge_7_data_item[0],
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
        filter_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_1() called")

    # set user and message variables for phantom.prompt call

    user = "Administrator"
    message = """The container {0} with severity {1} has IPs outside our countries.\n\n{2}\n"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "container:severity",
        "format_2:formatted_data"
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
        },
        {
            "prompt": "What message would you like on the HUD card",
            "options": {
                "type": "message",
            },
        }
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=1, name="prompt_1", parameters=parameters, response_types=response_types, callback=decision_2, drop_none=False)

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
        playbook_sep12demochild_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_1() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["my_geo:action_result.data.*.country_name", "!=", ""]
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


def format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_2() called")

    template = """%%\nIP: {0} is from: {1}\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_1:my_geo:action_result.parameter.ip",
        "filtered-data:filter_1:condition_1:my_geo:action_result.data.*.country_name"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_2")

    prompt_1(container=container)

    return


def playbook_sep12demochild_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_sep12demochild_1() called")

    prompt_1_result_data = phantom.collect2(container=container, datapath=["prompt_1:action_result.summary.responses.1"], action_results=results)
    filtered_result_0_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:my_geo:action_result.parameter.ip"])
    list_merge_7_data = phantom.collect2(container=container, datapath=["list_merge_7:custom_function_result.data.*.item"])
    my_geo_result_data = phantom.collect2(container=container, datapath=["my_geo:action_result.parameter.ip"], action_results=results)

    prompt_1_summary_responses_1 = [item[0] for item in prompt_1_result_data]
    filtered_result_0_parameter_ip = [item[0] for item in filtered_result_0_data_filter_1]
    list_merge_7_data___item = [item[0] for item in list_merge_7_data]
    my_geo_parameter_ip = [item[0] for item in my_geo_result_data]

    ip_combined_value = phantom.concatenate(filtered_result_0_parameter_ip, list_merge_7_data___item, my_geo_parameter_ip)

    inputs = {
        "hud_msg": prompt_1_summary_responses_1,
        "ip": ip_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "chris/sep12demochild", returns the playbook_run_id
    playbook_run_id = phantom.playbook("chris/sep12demochild", container=container, name="playbook_sep12demochild_1", callback=prompt_3, inputs=inputs)

    return


def list_merge_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("list_merge_7() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.destinationAddress","artifact:*.cef.sourceAddress","artifact:*.id"])

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]
    container_artifact_cef_item_1 = [item[1] for item in container_artifact_data]

    parameters = []

    parameters.append({
        "input_1": container_artifact_cef_item_0,
        "input_2": container_artifact_cef_item_1,
        "input_3": None,
        "input_4": None,
        "input_5": None,
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

    phantom.custom_function(custom_function="community/list_merge", parameters=parameters, name="list_merge_7", callback=my_geo)

    return


def prompt_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_3() called")

    # set user and message variables for phantom.prompt call

    user = "Administrator"
    message = """The response from child pb was:\n{0}"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_sep12demochild_1:playbook_output:response"
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_3", parameters=parameters)

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