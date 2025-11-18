"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'list_merge_3' block
    list_merge_3(container=container)

    return

@phantom.playbook_block()
def my_geolocate(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("my_geolocate() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # This is a comment in the python code
    ################################################################################

    list_merge_3__result = phantom.collect2(container=container, datapath=["list_merge_3:custom_function_result.data.item"])

    parameters = []

    # build parameters list for 'my_geolocate' call
    for list_merge_3__result_item in list_merge_3__result:
        if list_merge_3__result_item[0] is not None:
            parameters.append({
                "ip": list_merge_3__result_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("geolocate ip", parameters=parameters, name="my_geolocate", assets=["maxmind"], callback=my_geolocate_callback)

    return


@phantom.playbook_block()
def my_geolocate_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("my_geolocate_callback() called")

    
    debug_4(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    filter_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="and",
        conditions=[
            ["filtered-data:filter_1:condition_1:my_geolocate:action_result.data.*.country_iso_code", "!=", "US"],
            ["filtered-data:filter_1:condition_1:my_geolocate:action_result.data.*.country_iso_code", "!=", "MX"],
            ["filtered-data:filter_1:condition_1:my_geolocate:action_result.data.*.country_iso_code", "!=", "CA"],
            ["filtered-data:filter_1:condition_1:my_geolocate:action_result.data.*.country_iso_code", "!=", "DE"]
        ],
        conditions_dps=[
            ["filtered-data:filter_1:condition_1:my_geolocate:action_result.data.*.country_iso_code", "!=", "US"],
            ["filtered-data:filter_1:condition_1:my_geolocate:action_result.data.*.country_iso_code", "!=", "MX"],
            ["filtered-data:filter_1:condition_1:my_geolocate:action_result.data.*.country_iso_code", "!=", "CA"],
            ["filtered-data:filter_1:condition_1:my_geolocate:action_result.data.*.country_iso_code", "!=", "DE"]
        ],
        name="decision_1:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        format_ip_and_country_list(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    set_label(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def set_label(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_label() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_label(container=container, label="lowsev")

    container = phantom.get_container(container.get('id', None))

    pin_6(container=container)

    return


@phantom.playbook_block()
def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("prompt_1() called")

    # set approver and message variables for phantom.prompt call

    user = None
    role = "Administrator"
    message = """The Event {0} with current severity {1} has IP(s) not in our list.\n\n{2}"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "container:severity",
        "format_ip_and_country_list:formatted_data"
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
        },
        {
            "prompt": "Please provide a reason",
            "options": {
                "type": "message",
                "required": True,
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=5, name="prompt_1", parameters=parameters, response_types=response_types, callback=decision_2)

    return


@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_1:action_result.summary.responses.0", "!=", "No"]
        ],
        conditions_dps=[
            ["prompt_1:action_result.summary.responses.0", "!=", "No"]
        ],
        name="decision_2:condition_1",
        case_sensitive=False,
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        playbook_lab_demo_nov_2025_child_pb_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def list_merge_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("list_merge_3() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.destinationAddress","artifact:*.cef.sourceAddress","artifact:*.cef.deviceAddress","artifact:*.id"])

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

    phantom.custom_function(custom_function="community/list_merge", parameters=parameters, name="list_merge_3", callback=my_geolocate)

    return


@phantom.playbook_block()
def debug_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_4() called")

    my_geolocate_result_data = phantom.collect2(container=container, datapath=["my_geolocate:action_result.data","my_geolocate:action_result.parameter.context.artifact_id"], action_results=results)

    my_geolocate_result_item_0 = [item[0] for item in my_geolocate_result_data]

    parameters = []

    parameters.append({
        "input_1": my_geolocate_result_item_0,
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

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_4")

    return


@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_1() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["my_geolocate:action_result.data.*.country_iso_code", "!=", None]
        ],
        conditions_dps=[
            ["my_geolocate:action_result.data.*.country_iso_code", "!=", None]
        ],
        name="filter_1:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        decision_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def format_ip_and_country_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_ip_and_country_list() called")

    template = """%%\nIP: {0} is from {1} (ISO {2})\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_1:my_geolocate:action_result.parameter.ip",
        "filtered-data:filter_1:condition_1:my_geolocate:action_result.data.*.country_name",
        "filtered-data:filter_1:condition_1:my_geolocate:action_result.data.*.country_iso_code"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_ip_and_country_list")

    prompt_1(container=container)

    return


@phantom.playbook_block()
def pin_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("pin_6() called")

    filtered_result_0_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:my_geolocate:action_result.data.*.country_name","filtered-data:filter_1:condition_1:my_geolocate:action_result.parameter.ip"])

    filtered_result_0_data___country_name = [item[0] for item in filtered_result_0_data_filter_1]
    filtered_result_0_parameter_ip = [item[1] for item in filtered_result_0_data_filter_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=filtered_result_0_data___country_name, message=filtered_result_0_parameter_ip, pin_style="blue", pin_type="card")

    return


@phantom.playbook_block()
def playbook_lab_demo_nov_2025_child_pb_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_lab_demo_nov_2025_child_pb_1() called")

    filtered_result_0_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:my_geolocate:action_result.parameter.ip","filtered-data:filter_1:condition_1:my_geolocate:action_result.data.*.country_name"])
    prompt_1_result_data = phantom.collect2(container=container, datapath=["prompt_1:action_result.summary.responses.1"], action_results=results)

    filtered_result_0_parameter_ip = [item[0] for item in filtered_result_0_data_filter_1]
    filtered_result_0_data___country_name = [item[1] for item in filtered_result_0_data_filter_1]
    prompt_1_summary_responses_1 = [item[0] for item in prompt_1_result_data]

    inputs = {
        "ips": filtered_result_0_parameter_ip,
        "countries": filtered_result_0_data___country_name,
        "reason_for_high_severity": prompt_1_summary_responses_1,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "chris/lab demo nov 2025 child pb", returns the playbook_run_id
    playbook_run_id = phantom.playbook("chris/lab demo nov 2025 child pb", container=container, name="playbook_lab_demo_nov_2025_child_pb_1", callback=decision_3, inputs=inputs)

    return


@phantom.playbook_block()
def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_3() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["playbook_lab_demo_nov_2025_child_pb_1:playbook_output:risk_score", ">", 100]
        ],
        conditions_dps=[
            ["playbook_lab_demo_nov_2025_child_pb_1:playbook_output:risk_score", ">", 100]
        ],
        name="decision_3:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        add_note_7(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    add_note_8(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def add_note_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_note_7() called")

    playbook_lab_demo_nov_2025_child_pb_1_output_risk_score = phantom.collect2(container=container, datapath=["playbook_lab_demo_nov_2025_child_pb_1:playbook_output:risk_score"])

    playbook_lab_demo_nov_2025_child_pb_1_output_risk_score_values = [item[0] for item in playbook_lab_demo_nov_2025_child_pb_1_output_risk_score]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=playbook_lab_demo_nov_2025_child_pb_1_output_risk_score_values, note_format="markdown", note_type="general", title="High risk score")

    promote_to_case_5(container=container)

    return


@phantom.playbook_block()
def add_note_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_note_8() called")

    playbook_lab_demo_nov_2025_child_pb_1_output_risk_score = phantom.collect2(container=container, datapath=["playbook_lab_demo_nov_2025_child_pb_1:playbook_output:risk_score"])

    playbook_lab_demo_nov_2025_child_pb_1_output_risk_score_values = [item[0] for item in playbook_lab_demo_nov_2025_child_pb_1_output_risk_score]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=playbook_lab_demo_nov_2025_child_pb_1_output_risk_score_values, note_format="markdown", note_type="general", title="Low risk score")

    return


@phantom.playbook_block()
def promote_to_case_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("promote_to_case_5() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.promote(container=container, template="Vulnerability Disclosure")

    container = phantom.get_container(container.get('id', None))

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################
    phantom.debug("Chris was here")
    
    
    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return