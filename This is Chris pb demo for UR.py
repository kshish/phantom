"""
This is a comment for the whole playook.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'list_merge_5' block
    list_merge_5(container=container)

    return

@phantom.playbook_block()
def my_geolocate_action(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("my_geolocate_action() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # this action takes an IP address and gives more geo location info
    # 
    # Chris adding comments into the python code indirectly
    ################################################################################

    list_merge_5__result = phantom.collect2(container=container, datapath=["list_merge_5:custom_function_result.data.item"])

    parameters = []

    # build parameters list for 'my_geolocate_action' call
    for list_merge_5__result_item in list_merge_5__result:
        if list_merge_5__result_item[0] is not None:
            parameters.append({
                "ip": list_merge_5__result_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("geolocate ip", parameters=parameters, name="my_geolocate_action", assets=["maxmind"], callback=filter_1)

    return


@phantom.playbook_block()
def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("prompt_1() called")

    # set approver and message variables for phantom.prompt call

    user = "soardev"
    role = None
    message = """IP is not in our list.\n\n{0}"""

    # parameter list for template variable replacement
    parameters = [
        "format_list:formatted_data"
    ]

    # responses
    response_types = [
        {
            "prompt": "Would you like to set severity to High?",
            "options": {
                "type": "list",
                "required": True,
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        },
        {
            "prompt": "Please provide the reason",
            "options": {
                "type": "message",
                "required": True,
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=1, name="prompt_1", parameters=parameters, response_types=response_types, callback=prompt_1_callback, drop_none=False)

    return


@phantom.playbook_block()
def prompt_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("prompt_1_callback() called")

    
    decision_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    debug_4(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_2() called")

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
        name="decision_2:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        playbook_child_demo_ur_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def debug_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_3() called")

    my_geolocate_action_result_data = phantom.collect2(container=container, datapath=["my_geolocate_action:action_result.status","my_geolocate_action:action_result.data.*.country_iso_code","my_geolocate_action:action_result.data.*.country_name","my_geolocate_action:action_result.parameter.context.artifact_id"], action_results=results)

    my_geolocate_action_result_item_0 = [item[0] for item in my_geolocate_action_result_data]
    my_geolocate_action_result_item_1 = [item[1] for item in my_geolocate_action_result_data]
    my_geolocate_action_result_item_2 = [item[2] for item in my_geolocate_action_result_data]

    parameters = []

    parameters.append({
        "input_1": my_geolocate_action_result_item_0,
        "input_2": my_geolocate_action_result_item_1,
        "input_3": my_geolocate_action_result_item_2,
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

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_3")

    return


@phantom.playbook_block()
def debug_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_4() called")

    prompt_1_result_data = phantom.collect2(container=container, datapath=["prompt_1:action_result.status","prompt_1:action_result.parameter.message","prompt_1:action_result.summary.user","prompt_1:action_result.parameter.ttl","prompt_1:action_result.summary.answered_at","prompt_1:action_result.summary.sent_at","prompt_1:action_result.summary.responses.0","prompt_1:action_result.parameter.context.artifact_id"], action_results=results)

    prompt_1_result_item_0 = [item[0] for item in prompt_1_result_data]
    prompt_1_parameter_message = [item[1] for item in prompt_1_result_data]
    prompt_1_summary_user = [item[2] for item in prompt_1_result_data]
    prompt_1_parameter_ttl = [item[3] for item in prompt_1_result_data]
    prompt_1_summary_answered_at = [item[4] for item in prompt_1_result_data]
    prompt_1_summary_sent_at = [item[5] for item in prompt_1_result_data]
    prompt_1_summary_responses_0 = [item[6] for item in prompt_1_result_data]

    parameters = []

    parameters.append({
        "input_1": prompt_1_result_item_0,
        "input_2": prompt_1_parameter_message,
        "input_3": prompt_1_summary_user,
        "input_4": prompt_1_parameter_ttl,
        "input_5": prompt_1_summary_answered_at,
        "input_6": prompt_1_summary_sent_at,
        "input_7": prompt_1_summary_responses_0,
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

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_4")

    return


@phantom.playbook_block()
def list_merge_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("list_merge_5() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.cef.destinationAddress","artifact:*.cef.deviceAddress","artifact:*.cef.destinationMacAddress","artifact:*.cef.destinationTranslatedAddress","artifact:*.cef.sourceMacAddress","artifact:*.id"])

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]
    container_artifact_cef_item_1 = [item[1] for item in container_artifact_data]
    container_artifact_cef_item_2 = [item[2] for item in container_artifact_data]
    container_artifact_cef_item_3 = [item[3] for item in container_artifact_data]
    container_artifact_cef_item_4 = [item[4] for item in container_artifact_data]
    container_artifact_cef_item_5 = [item[5] for item in container_artifact_data]

    parameters = []

    parameters.append({
        "input_1": container_artifact_cef_item_0,
        "input_2": container_artifact_cef_item_1,
        "input_3": container_artifact_cef_item_2,
        "input_4": container_artifact_cef_item_3,
        "input_5": container_artifact_cef_item_4,
        "input_6": container_artifact_cef_item_5,
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

    phantom.custom_function(custom_function="community/list_merge", parameters=parameters, name="list_merge_5", callback=my_geolocate_action)

    return


@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_1() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["my_geolocate_action:action_result.data.*.country_iso_code", "!=", None]
        ],
        conditions_dps=[
            ["my_geolocate_action:action_result.data.*.country_iso_code", "!=", None]
        ],
        name="filter_1:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def format_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_list() called")

    template = """%%\nIP: {0} is from {1} ({2})\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_2:condition_2:my_geolocate_action:action_result.parameter.ip",
        "filtered-data:filter_2:condition_2:my_geolocate_action:action_result.data.*.country_name",
        "filtered-data:filter_2:condition_2:my_geolocate_action:action_result.data.*.country_iso_code"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_list")

    prompt_1(container=container)

    return


@phantom.playbook_block()
def pin_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("pin_8() called")

    filtered_result_0_data_filter_2 = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_1:my_geolocate_action:action_result.data.*.country_name"])

    filtered_result_0_data___country_name = [item[0] for item in filtered_result_0_data_filter_2]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=filtered_result_0_data___country_name, message="IP is in our list", pin_style="blue", pin_type="card")

    set_label_2(container=container)

    return


@phantom.playbook_block()
def playbook_child_demo_ur_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_child_demo_ur_1() called")

    prompt_1_result_data = phantom.collect2(container=container, datapath=["prompt_1:action_result.summary.responses.1"], action_results=results)
    filtered_result_0_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:my_geolocate_action:action_result.data.*.country_name"])

    prompt_1_summary_responses_1 = [item[0] for item in prompt_1_result_data]
    filtered_result_0_data___country_name = [item[0] for item in filtered_result_0_data_filter_1]

    inputs = {
        "reason": prompt_1_summary_responses_1,
        "country_name": filtered_result_0_data___country_name,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "Chris/child demo UR", returns the playbook_run_id
    playbook_run_id = phantom.playbook("Chris/child demo UR", container=container, name="playbook_child_demo_ur_1", callback=decision_3, inputs=inputs)

    return


@phantom.playbook_block()
def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_3() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["playbook_child_demo_ur_1:playbook_output:risk_score", ">", 99]
        ],
        conditions_dps=[
            ["playbook_child_demo_ur_1:playbook_output:risk_score", ">", 99]
        ],
        name="decision_3:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        format_risk_score_msg(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    add_comment_10(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def format_risk_score_msg(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_risk_score_msg() called")

    template = """High Risk Score!!!!\n\nRisk score: {0}\n"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_child_demo_ur_1:playbook_output:risk_score"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_risk_score_msg")

    add_comment_9(container=container)

    return


@phantom.playbook_block()
def add_comment_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_comment_9() called")

    format_risk_score_msg = phantom.get_format_data(name="format_risk_score_msg")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_risk_score_msg)

    return


@phantom.playbook_block()
def add_comment_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_comment_10() called")

    playbook_child_demo_ur_1_output_risk_score = phantom.collect2(container=container, datapath=["playbook_child_demo_ur_1:playbook_output:risk_score"])

    playbook_child_demo_ur_1_output_risk_score_values = [item[0] for item in playbook_child_demo_ur_1_output_risk_score]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=playbook_child_demo_ur_1_output_risk_score_values)

    return


@phantom.playbook_block()
def set_label_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_label_2() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_label(container=container, label="in our list")

    container = phantom.get_container(container.get('id', None))

    return


@phantom.playbook_block()
def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_2() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filter_1:condition_1:my_geolocate_action:action_result.data.*.country_iso_code", "in", "custom_list:country ISO Codes"]
        ],
        conditions_dps=[
            ["filtered-data:filter_1:condition_1:my_geolocate_action:action_result.data.*.country_iso_code", "in", "custom_list:country ISO Codes"]
        ],
        name="filter_2:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        pin_8(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filter_1:condition_1:my_geolocate_action:action_result.data.*.country_iso_code", "not in", "custom_list:country ISO Codes"]
        ],
        conditions_dps=[
            ["filtered-data:filter_1:condition_1:my_geolocate_action:action_result.data.*.country_iso_code", "not in", "custom_list:country ISO Codes"]
        ],
        name="filter_2:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        format_list(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################
    phantom.debug("Chris wuz here")
    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return