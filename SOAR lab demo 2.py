"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


################################################################################
## Global Custom Code Start
################################################################################




################################################################################
## Global Custom Code End
################################################################################

def on_start(container):
    phantom.debug('on_start() called')

    # call 'list_merge_5' block
    list_merge_5(container=container)

    return

def geolocate_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("geolocate_ip_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    list_merge_5_data = phantom.collect2(container=container, datapath=["list_merge_5:custom_function_result.data.*.item"])

    parameters = []

    # build parameters list for 'geolocate_ip_1' call
    for list_merge_5_data_item in list_merge_5_data:
        if list_merge_5_data_item[0] is not None:
            parameters.append({
                "ip": list_merge_5_data_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here.	
    phantom.debug(parameters)
    phantom.debug("chris wuz here in the geo locate block")
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("geolocate ip", parameters=parameters, name="geolocate_ip_1", assets=["maxmind"], callback=filter_out_none)

    return


def ask_for_high_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("ask_for_high_severity() called")

    # set user and message variables for phantom.prompt call

    user = "admin"
    message = """An IP in {0} container is outside our countries list.\n\n{1}\n"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "format_1:formatted_data"
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
        },
        {
            "prompt": "What Severity",
            "options": {
                "type": "list",
                "choices": [
                    "low",
                    "medium",
                    "high",
                    "critical"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=1, name="ask_for_high_severity", parameters=parameters, response_types=response_types, callback=decide_on_response)

    return


def decide_on_response(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decide_on_response() called")

    ################################################################################
    # this decision block evaluates the response from the prompt.  
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["ask_for_high_severity:action_result.summary.responses.0", "==", "Yes"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        playbook_soar_child_pin_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def filter_out_none(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_out_none() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["geolocate_ip_1:action_result.data.*.country_name", "!=", None]
        ],
        name="filter_out_none:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_and_multi_direction(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["geolocate_ip_1:action_result.data.*.country_name", "==", ""]
        ],
        name="filter_out_none:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        pin_4(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_1() called")

    template = """%%\nthe ip: {0} is from {1}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_out_none:condition_1:geolocate_ip_1:action_result.parameter.ip",
        "filtered-data:filter_out_none:condition_1:geolocate_ip_1:action_result.data.*.country_name"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    ask_for_high_severity(container=container)

    return


def list_merge_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("list_merge_5() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.cef.destinationAddress","artifact:*.cef.src_ip","artifact:*.id"])

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]
    container_artifact_cef_item_1 = [item[1] for item in container_artifact_data]
    container_artifact_cef_item_2 = [item[2] for item in container_artifact_data]

    parameters = []

    parameters.append({
        "input_1": container_artifact_cef_item_0,
        "input_2": container_artifact_cef_item_1,
        "input_3": container_artifact_cef_item_2,
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

    phantom.custom_function(custom_function="community/list_merge", parameters=parameters, name="list_merge_5", callback=geolocate_ip_1)

    return


def playbook_soar_child_pin_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_soar_child_pin_1() called")

    ask_for_high_severity_result_data = phantom.collect2(container=container, datapath=["ask_for_high_severity:action_result.summary.responses.1","ask_for_high_severity:action_result.summary.responses.2"], action_results=results)
    filtered_result_0_data_filter_and_multi_direction = phantom.collect2(container=container, datapath=["filtered-data:filter_and_multi_direction:condition_2:geolocate_ip_1:action_result.data.*.country_name","filtered-data:filter_and_multi_direction:condition_2:geolocate_ip_1:action_result.parameter.ip"])

    ask_for_high_severity_summary_responses_1 = [item[0] for item in ask_for_high_severity_result_data]
    ask_for_high_severity_summary_responses_2 = [item[1] for item in ask_for_high_severity_result_data]
    filtered_result_0_data___country_name = [item[0] for item in filtered_result_0_data_filter_and_multi_direction]
    filtered_result_0_parameter_ip = [item[1] for item in filtered_result_0_data_filter_and_multi_direction]

    inputs = {
        "hud_msg": ask_for_high_severity_summary_responses_1,
        "severity": ask_for_high_severity_summary_responses_2,
        "countries": filtered_result_0_data___country_name,
        "list_of_ip": filtered_result_0_parameter_ip,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/SOAR Child pin", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/SOAR Child pin", container=container, name="playbook_soar_child_pin_1", callback=prompt_2, inputs=inputs)

    return


def prompt_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_2() called")

    # set user and message variables for phantom.prompt call

    user = "admin"
    message = """thoughts from Child PB {0}"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_soar_child_pin_1:playbook_output:think"
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_2", parameters=parameters)

    return


def filter_and_multi_direction(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_and_multi_direction() called")

    ################################################################################
    # this filter will cause the playbook to go into mulitple direction if ip our 
    # in and outside of friendlies
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="or",
        conditions=[
            ["filtered-data:filter_out_none:condition_1:geolocate_ip_1:action_result.data.*.country_name", "==", "United States"],
            ["filtered-data:filter_out_none:condition_1:geolocate_ip_1:action_result.data.*.country_name", "==", "Netherlands"],
            ["filtered-data:filter_out_none:condition_1:geolocate_ip_1:action_result.data.*.country_name", "==", "India"]
        ],
        name="filter_and_multi_direction:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        pin_6(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["filtered-data:filter_out_none:condition_1:geolocate_ip_1:action_result.data.*.country_name", "!=", "United States"],
            ["filtered-data:filter_out_none:condition_1:geolocate_ip_1:action_result.data.*.country_name", "!=", "Netherlands"],
            ["", "!=", "India"]
        ],
        name="filter_and_multi_direction:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        format_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


def pin_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pin_6() called")

    filtered_result_0_data_filter_and_multi_direction = phantom.collect2(container=container, datapath=["filtered-data:filter_and_multi_direction:condition_1:geolocate_ip_1:action_result.parameter.ip","filtered-data:filter_and_multi_direction:condition_1:geolocate_ip_1:action_result.data.*.country_name"])

    filtered_result_0_parameter_ip = [item[0] for item in filtered_result_0_data_filter_and_multi_direction]
    filtered_result_0_data___country_name = [item[1] for item in filtered_result_0_data_filter_and_multi_direction]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=filtered_result_0_parameter_ip, message=filtered_result_0_data___country_name, pin_style="yellow", pin_type="card")

    return

def pin_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pin_4() called")

    filtered_result_0_data_filter_out_none = phantom.collect2(container=container, datapath=["filtered-data:filter_out_none:condition_2:geolocate_ip_1:action_result.parameter.ip","filtered-data:filter_out_none:condition_2:geolocate_ip_1:action_result.data.*.country_name"])

    filtered_result_0_parameter_ip = [item[0] for item in filtered_result_0_data_filter_out_none]
    filtered_result_0_data___country_name = [item[1] for item in filtered_result_0_data_filter_out_none]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=filtered_result_0_parameter_ip, message=filtered_result_0_data___country_name, pin_style="grey", pin_type="card")

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