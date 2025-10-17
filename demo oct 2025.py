"""
This ends being comments in the code
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'merge_bunch_of_ip_fields' block
    merge_bunch_of_ip_fields(container=container)

    return

@phantom.playbook_block()
def my_geolocate_blagh(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("my_geolocate_blagh() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    merge_bunch_of_ip_fields__result = phantom.collect2(container=container, datapath=["merge_bunch_of_ip_fields:custom_function_result.data.item"])

    parameters = []

    # build parameters list for 'my_geolocate_blagh' call
    for merge_bunch_of_ip_fields__result_item in merge_bunch_of_ip_fields__result:
        if merge_bunch_of_ip_fields__result_item[0] is not None:
            parameters.append({
                "ip": merge_bunch_of_ip_fields__result_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("geolocate ip", parameters=parameters, name="my_geolocate_blagh", assets=["maxmind"], callback=my_geolocate_blagh_callback)

    return


@phantom.playbook_block()
def my_geolocate_blagh_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("my_geolocate_blagh_callback() called")

    
    debug_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    filter_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_1() called")

    name_value = container.get("name", None)
    label_value = container.get("label", None)
    my_geolocate_blagh_result_data = phantom.collect2(container=container, datapath=["my_geolocate_blagh:action_result.parameter.ip","my_geolocate_blagh:action_result.data.*.country_name","my_geolocate_blagh:action_result.data.*.country_iso_code","my_geolocate_blagh:action_result.parameter.context.artifact_id"], action_results=results)

    my_geolocate_blagh_parameter_ip = [item[0] for item in my_geolocate_blagh_result_data]
    my_geolocate_blagh_result_item_1 = [item[1] for item in my_geolocate_blagh_result_data]
    my_geolocate_blagh_result_item_2 = [item[2] for item in my_geolocate_blagh_result_data]

    parameters = []

    parameters.append({
        "input_1": ["Chris was here"],
        "input_2": my_geolocate_blagh_parameter_ip,
        "input_3": my_geolocate_blagh_result_item_1,
        "input_4": my_geolocate_blagh_result_item_2,
        "input_5": name_value,
        "input_6": label_value,
        "input_7": my_geolocate_blagh_result_item_1,
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


@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="and",
        conditions=[
            ["filtered-data:filter_1:condition_1:my_geolocate_blagh:action_result.data.*.country_iso_code", "!=", "US"],
            ["filtered-data:filter_1:condition_1:my_geolocate_blagh:action_result.data.*.country_iso_code", "!=", "CA"],
            ["filtered-data:filter_1:condition_1:my_geolocate_blagh:action_result.data.*.country_iso_code", "!=", "TD"],
            ["filtered-data:filter_1:condition_1:my_geolocate_blagh:action_result.data.*.country_iso_code", "!=", "DE"]
        ],
        conditions_dps=[
            ["filtered-data:filter_1:condition_1:my_geolocate_blagh:action_result.data.*.country_iso_code", "!=", "US"],
            ["filtered-data:filter_1:condition_1:my_geolocate_blagh:action_result.data.*.country_iso_code", "!=", "CA"],
            ["filtered-data:filter_1:condition_1:my_geolocate_blagh:action_result.data.*.country_iso_code", "!=", "TD"],
            ["filtered-data:filter_1:condition_1:my_geolocate_blagh:action_result.data.*.country_iso_code", "!=", "DE"]
        ],
        name="decision_2:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        prompt_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    add_comment_5(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def set_severity_to_low(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
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


@phantom.playbook_block()
def set_severity_to_high(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
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


@phantom.playbook_block()
def add_comment_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_comment_5() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="set sev to low")

    set_severity_to_low(container=container)

    return


@phantom.playbook_block()
def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("prompt_1() called")

    # set approver and message variables for phantom.prompt call

    user = None
    role = "Administrator"
    message = """The event {0} with severity {1}\n\nIP is not in our list of countries.\n\nIP: {2} is from: {3} ISO: {4}{5}\n"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "container:severity",
        "filtered-data:filter_1:condition_1:my_geolocate_blagh:action_result.parameter.ip",
        "filtered-data:filter_1:condition_1:my_geolocate_blagh:action_result.data.*.country_name",
        "filtered-data:filter_1:condition_1:my_geolocate_blagh:action_result.data.*.country_iso_code",
        ""
    ]

    # responses
    response_types = [
        {
            "prompt": "Would you like to change severity to High?",
            "options": {
                "type": "list",
                "required": True,
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=1, name="prompt_1", parameters=parameters, response_types=response_types, callback=prompt_1_callback)

    return


@phantom.playbook_block()
def prompt_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("prompt_1_callback() called")

    
    evaluate_response(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    debug_6(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def evaluate_response(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("evaluate_response() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="or",
        conditions=[
            ["prompt_1:action_result.summary.responses.0", "==", "Yes"],
            ["prompt_1:action_result.status", "==", "failed"]
        ],
        conditions_dps=[
            ["prompt_1:action_result.summary.responses.0", "==", "Yes"],
            ["prompt_1:action_result.status", "==", "failed"]
        ],
        name="evaluate_response:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        set_severity_to_high(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def debug_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_6() called")

    prompt_1_result_data = phantom.collect2(container=container, datapath=["prompt_1:action_result.status","prompt_1:action_result.parameter.context.artifact_id"], action_results=results)

    prompt_1_result_item_0 = [item[0] for item in prompt_1_result_data]

    parameters = []

    parameters.append({
        "input_1": prompt_1_result_item_0,
        "input_2": None,
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

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_6")

    return


@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_1() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["my_geolocate_blagh:action_result.data.*.country_name", "!=", None]
        ],
        conditions_dps=[
            ["my_geolocate_blagh:action_result.data.*.country_name", "!=", None]
        ],
        name="filter_1:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        decision_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def merge_bunch_of_ip_fields(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("merge_bunch_of_ip_fields() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.destinationAddress","artifact:*.cef.deviceAddress","artifact:*.cef.sourceAddress","artifact:*.id"])

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

    phantom.custom_function(custom_function="community/list_merge", parameters=parameters, name="merge_bunch_of_ip_fields", callback=my_geolocate_blagh)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################
    phantom.debug("Chris was here at the end block")
    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return