"""
this is a comment
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'list_merge_4' block
    list_merge_4(container=container)

    return

@phantom.playbook_block()
def my_geolocate_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("my_geolocate_ip() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    list_merge_4__result = phantom.collect2(container=container, datapath=["list_merge_4:custom_function_result.data.item"])

    parameters = []

    # build parameters list for 'my_geolocate_ip' call
    for list_merge_4__result_item in list_merge_4__result:
        if list_merge_4__result_item[0] is not None:
            parameters.append({
                "ip": list_merge_4__result_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("geolocate ip", parameters=parameters, name="my_geolocate_ip", assets=["maxmind"], callback=filter_2)

    return


@phantom.playbook_block()
def decide_if_ip_is_in_our_list_of_countries(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decide_if_ip_is_in_our_list_of_countries() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["filtered-data:filter_2:condition_1:my_geolocate_ip:action_result.data.*.country_iso_code", "not in", "custom_list:countries iso codes"]
        ],
        conditions_dps=[
            ["filtered-data:filter_2:condition_1:my_geolocate_ip:action_result.data.*.country_iso_code", "not in", "custom_list:countries iso codes"]
        ],
        name="decide_if_ip_is_in_our_list_of_countries:condition_1",
        case_sensitive=False,
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        format_ip_country_and_code_list(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    artifact_create_1(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def set_lowsev_label(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_lowsev_label() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_label(container=container, label="lowsev")

    container = phantom.get_container(container.get('id', None))

    return


@phantom.playbook_block()
def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("prompt_1() called")

    # set approver and message variables for phantom.prompt call

    user = None
    role = "Administrator"
    message = """The event {0} with current severity {1} has IP(s) not in our list.\n\n{2}\n"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "container:severity",
        "format_ip_country_and_code_list:formatted_data"
    ]

    # responses
    response_types = [
        {
            "prompt": "Would you like to change severity to High and other things?",
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
            "prompt": "Please provide a reason",
            "options": {
                "type": "message",
                "required": True,
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=1, name="prompt_1", parameters=parameters, response_types=response_types, callback=prompt_1_callback)

    return


@phantom.playbook_block()
def prompt_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("prompt_1_callback() called")

    
    decide_what_analyst_answered(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    debug_3(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def decide_what_analyst_answered(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decide_what_analyst_answered() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_1:action_result.summary.responses.0", "!=", "No"]
        ],
        conditions_dps=[
            ["prompt_1:action_result.summary.responses.0", "!=", "No"]
        ],
        name="decide_what_analyst_answered:condition_1",
        case_sensitive=False,
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        playbook_lab_demo_child_pb_mar_2026_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def debug_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_3() called")

    prompt_1_result_data = phantom.collect2(container=container, datapath=["prompt_1:action_result.status","prompt_1:action_result.summary.responses.0","prompt_1:action_result.parameter.context.artifact_id"], action_results=results)
    my_geolocate_ip_result_data = phantom.collect2(container=container, datapath=["my_geolocate_ip:action_result.parameter.ip","my_geolocate_ip:action_result.data","my_geolocate_ip:action_result.parameter.context.artifact_id"], action_results=results)

    prompt_1_result_item_0 = [item[0] for item in prompt_1_result_data]
    prompt_1_summary_responses_0 = [item[1] for item in prompt_1_result_data]
    my_geolocate_ip_parameter_ip = [item[0] for item in my_geolocate_ip_result_data]
    my_geolocate_ip_result_item_1 = [item[1] for item in my_geolocate_ip_result_data]

    parameters = []

    parameters.append({
        "input_1": prompt_1_result_item_0,
        "input_2": prompt_1_summary_responses_0,
        "input_3": my_geolocate_ip_parameter_ip,
        "input_4": my_geolocate_ip_result_item_1,
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
def list_merge_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("list_merge_4() called")

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

    phantom.custom_function(custom_function="community/list_merge", parameters=parameters, name="list_merge_4", callback=my_geolocate_ip)

    return


@phantom.playbook_block()
def format_ip_country_and_code_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_ip_country_and_code_list() called")

    template = """%%\nIP: {0} is from {1} (ISO Code: {2} )\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_2:condition_1:my_geolocate_ip:action_result.parameter.ip",
        "filtered-data:filter_2:condition_1:my_geolocate_ip:action_result.data.*.country_name",
        "filtered-data:filter_2:condition_1:my_geolocate_ip:action_result.data.*.country_iso_code"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_ip_country_and_code_list")

    prompt_1(container=container)

    return


@phantom.playbook_block()
def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_2() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["my_geolocate_ip:action_result.data.*.country_iso_code", "!=", None]
        ],
        conditions_dps=[
            ["my_geolocate_ip:action_result.data.*.country_iso_code", "!=", None]
        ],
        name="filter_2:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        decide_if_ip_is_in_our_list_of_countries(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def playbook_lab_demo_child_pb_mar_2026_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_lab_demo_child_pb_mar_2026_1() called")

    filtered_result_0_data_filter_2 = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_1:my_geolocate_ip:action_result.parameter.ip","filtered-data:filter_2:condition_1:my_geolocate_ip:action_result.data.*.continent_name"])
    prompt_1_result_data = phantom.collect2(container=container, datapath=["prompt_1:action_result.summary.responses.1"], action_results=results)

    filtered_result_0_parameter_ip = [item[0] for item in filtered_result_0_data_filter_2]
    filtered_result_0_data___continent_name = [item[1] for item in filtered_result_0_data_filter_2]
    prompt_1_summary_responses_1 = [item[0] for item in prompt_1_result_data]

    inputs = {
        "ips": filtered_result_0_parameter_ip,
        "countries": filtered_result_0_data___continent_name,
        "reason_for_high_severity": prompt_1_summary_responses_1,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "abc/lab demo child pb mar 2026", returns the playbook_run_id
    playbook_run_id = phantom.playbook("abc/lab demo child pb mar 2026", container=container, name="playbook_lab_demo_child_pb_mar_2026_1", callback=decision_3, inputs=inputs)

    return


@phantom.playbook_block()
def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_3() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["playbook_lab_demo_child_pb_mar_2026_1:playbook_output:risk_score", ">", 100]
        ],
        conditions_dps=[
            ["playbook_lab_demo_child_pb_mar_2026_1:playbook_output:risk_score", ">", 100]
        ],
        name="decision_3:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        format_risk_score(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    add_note_9(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def add_note_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_note_8() called")

    format_risk_score = phantom.get_format_data(name="format_risk_score")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=format_risk_score, note_format="markdown", note_type="general", title="High Risk score")

    return


@phantom.playbook_block()
def format_risk_score(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_risk_score() called")

    template = """Risk {0} score of """

    # parameter list for template variable replacement
    parameters = [
        "playbook_lab_demo_child_pb_mar_2026_1:playbook_output:risk_score"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_risk_score")

    add_note_8(container=container)

    return


@phantom.playbook_block()
def add_note_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_note_9() called")

    playbook_lab_demo_child_pb_mar_2026_1_output_risk_score = phantom.collect2(container=container, datapath=["playbook_lab_demo_child_pb_mar_2026_1:playbook_output:risk_score"])

    playbook_lab_demo_child_pb_mar_2026_1_output_risk_score_values = [item[0] for item in playbook_lab_demo_child_pb_mar_2026_1_output_risk_score]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=playbook_lab_demo_child_pb_mar_2026_1_output_risk_score_values, note_format="markdown", note_type="general", title="Not as high risk score")

    return


@phantom.playbook_block()
def artifact_create_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("artifact_create_1() called")

    my_geolocate_ip_result_data = phantom.collect2(container=container, datapath=["my_geolocate_ip:action_result.data.*.country_iso_code","my_geolocate_ip:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'artifact_create_1' call
    for my_geolocate_ip_result_item in my_geolocate_ip_result_data:
        parameters.append({
            "name": None,
            "tags": None,
            "label": None,
            "severity": None,
            "cef_field": "app",
            "cef_value": my_geolocate_ip_result_item[0],
            "container": None,
            "input_json": None,
            "cef_data_type": None,
            "run_automation": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_create", parameters=parameters, name="artifact_create_1", callback=set_lowsev_label)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################
    phantom.debug("chris was here")
    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return