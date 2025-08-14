"""

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
def geolocate_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("geolocate_ip_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    list_merge_4__result = phantom.collect2(container=container, datapath=["list_merge_4:custom_function_result.data.item"])

    parameters = []

    # build parameters list for 'geolocate_ip_1' call
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

    phantom.act("geolocate ip", parameters=parameters, name="geolocate_ip_1", assets=["maxmind"], callback=filter_1)

    return


@phantom.playbook_block()
def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("send_email_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    description_value = container.get("description", None)
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.cn1","artifact:*.id"])

    parameters = []

    # build parameters list for 'send_email_1' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None and description_value is not None:
            parameters.append({
                "cc": description_value,
                "to": container_artifact_item[0],
                "body": description_value,
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("send email", parameters=parameters, name="send_email_1", assets=["myemailserver"], callback=send_email_1_callback)

    return


@phantom.playbook_block()
def send_email_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("send_email_1_callback() called")

    
    debug_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    filter_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_1() called")

    geolocate_ip_1_result_data = phantom.collect2(container=container, datapath=["geolocate_ip_1:action_result.status","geolocate_ip_1:action_result.data.*.country_name","geolocate_ip_1:action_result.parameter.context.artifact_id"], action_results=results)
    send_email_1_result_data = phantom.collect2(container=container, datapath=["send_email_1:action_result.status","send_email_1:action_result.parameter.context.artifact_id"], action_results=results)

    geolocate_ip_1_result_item_0 = [item[0] for item in geolocate_ip_1_result_data]
    geolocate_ip_1_result_item_1 = [item[1] for item in geolocate_ip_1_result_data]
    send_email_1_result_item_0 = [item[0] for item in send_email_1_result_data]

    parameters = []

    parameters.append({
        "input_1": geolocate_ip_1_result_item_0,
        "input_2": send_email_1_result_item_0,
        "input_3": geolocate_ip_1_result_item_1,
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

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_1")

    return


@phantom.playbook_block()
def prompt_to_set_high_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("prompt_to_set_high_severity() called")

    # set approver and message variables for phantom.prompt call

    user = None
    role = "Administrator"
    message = """The event {0} with severity {1} has IPs not in our list.\n\n{2}\n\n"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "container:severity",
        "format_1:formatted_data"
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

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=1, name="prompt_to_set_high_severity", parameters=parameters, response_types=response_types, callback=decision_2)

    return


@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_to_set_high_severity:action_result.summary.responses.0", "!=", "No"]
        ],
        conditions_dps=[
            ["prompt_to_set_high_severity:action_result.summary.responses.0", "!=", "No"]
        ],
        name="decision_2:condition_1",
        case_sensitive=False,
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        playbook_aug_2025_child_pb_demo_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def list_merge_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("list_merge_4() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.cef.destinationAddress","artifact:*.cef.deviceAddress","artifact:*.id"])

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

    phantom.custom_function(custom_function="community/list_merge", parameters=parameters, name="list_merge_4", callback=geolocate_ip_1)

    return


@phantom.playbook_block()
def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_1() called")

    template = """%%\nIP: {0} is from country {1}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_1:geolocate_ip_1:action_result.parameter.ip",
        "filtered-data:filter_1:condition_1:geolocate_ip_1:action_result.data.*.country_name"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    prompt_to_set_high_severity(container=container)

    return


@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_1() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["geolocate_ip_1:action_result.data.*.country_name", "!=", None]
        ],
        conditions_dps=[
            ["geolocate_ip_1:action_result.data.*.country_name", "!=", None]
        ],
        name="filter_1:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        send_email_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def playbook_aug_2025_child_pb_demo_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_aug_2025_child_pb_demo_1() called")

    filtered_result_0_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:geolocate_ip_1:action_result.parameter.ip","filtered-data:filter_1:condition_1:geolocate_ip_1:action_result.data.*.country_name"])
    prompt_to_set_high_severity_result_data = phantom.collect2(container=container, datapath=["prompt_to_set_high_severity:action_result.summary.responses.1"], action_results=results)

    filtered_result_0_parameter_ip = [item[0] for item in filtered_result_0_data_filter_1]
    filtered_result_0_data___country_name = [item[1] for item in filtered_result_0_data_filter_1]
    prompt_to_set_high_severity_summary_responses_1 = [item[0] for item in prompt_to_set_high_severity_result_data]

    inputs = {
        "ip": filtered_result_0_parameter_ip,
        "country": filtered_result_0_data___country_name,
        "reason_for_high_severity": prompt_to_set_high_severity_summary_responses_1,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "chris/aug 2025 child pb demo", returns the playbook_run_id
    playbook_run_id = phantom.playbook("chris/aug 2025 child pb demo", container=container, name="playbook_aug_2025_child_pb_demo_1", callback=decision_3, inputs=inputs)

    return


@phantom.playbook_block()
def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_3() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["playbook_aug_2025_child_pb_demo_1:playbook_output:risk_score", ">", 99]
        ],
        conditions_dps=[
            ["playbook_aug_2025_child_pb_demo_1:playbook_output:risk_score", ">", 99]
        ],
        name="decision_3:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        promote_to_case_6(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    add_note_7(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def promote_to_case_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("promote_to_case_6() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.promote()

    container = phantom.get_container(container.get('id', None))

    return


@phantom.playbook_block()
def add_note_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_note_7() called")

    playbook_aug_2025_child_pb_demo_1_output_risk_score = phantom.collect2(container=container, datapath=["playbook_aug_2025_child_pb_demo_1:playbook_output:risk_score"])

    playbook_aug_2025_child_pb_demo_1_output_risk_score_values = [item[0] for item in playbook_aug_2025_child_pb_demo_1_output_risk_score]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=playbook_aug_2025_child_pb_demo_1_output_risk_score_values, note_format="markdown", note_type="general", title="Risk Score")

    container = phantom.get_container(container.get('id', None))

    return


@phantom.playbook_block()
def set_label_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_label_8() called")

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
def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_2() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filter_1:condition_1:geolocate_ip_1:action_result.data.*.country_name", "in", "custom_list:countries"]
        ],
        conditions_dps=[
            ["filtered-data:filter_1:condition_1:geolocate_ip_1:action_result.data.*.country_name", "in", "custom_list:countries"]
        ],
        name="filter_2:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        pin_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filter_1:condition_1:geolocate_ip_1:action_result.data.*.country_name", "not in", "custom_list:countries"]
        ],
        conditions_dps=[
            ["filtered-data:filter_1:condition_1:geolocate_ip_1:action_result.data.*.country_name", "not in", "custom_list:countries"]
        ],
        name="filter_2:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        pin_3(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def pin_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("pin_2() called")

    filtered_result_0_data_filter_2 = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_1:geolocate_ip_1:action_result.parameter.ip","filtered-data:filter_2:condition_1:geolocate_ip_1:action_result.data.*.country_name"])

    filtered_result_0_parameter_ip = [item[0] for item in filtered_result_0_data_filter_2]
    filtered_result_0_data___country_name = [item[1] for item in filtered_result_0_data_filter_2]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=filtered_result_0_parameter_ip, message=filtered_result_0_data___country_name, pin_style="blue", pin_type="card")

    return


@phantom.playbook_block()
def pin_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("pin_3() called")

    filtered_result_0_data_filter_2 = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_2:geolocate_ip_1:action_result.parameter.ip","filtered-data:filter_2:condition_2:geolocate_ip_1:action_result.data.*.country_name"])

    filtered_result_0_parameter_ip = [item[0] for item in filtered_result_0_data_filter_2]
    filtered_result_0_data___country_name = [item[1] for item in filtered_result_0_data_filter_2]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=filtered_result_0_parameter_ip, message=filtered_result_0_data___country_name, pin_style="red", pin_type="card")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################
    phantom.debug("chris was here at the end of the playbook")
    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return