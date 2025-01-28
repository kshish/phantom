"""
this will be a comment in the  code
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
def my_geolocate(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("my_geolocate() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    list_merge_5__result = phantom.collect2(container=container, datapath=["list_merge_5:custom_function_result.data.item"])

    parameters = []

    # build parameters list for 'my_geolocate' call
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

    phantom.act("geolocate ip", parameters=parameters, name="my_geolocate", assets=["maxmind"], callback=my_geolocate_callback)

    return


@phantom.playbook_block()
def my_geolocate_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("my_geolocate_callback() called")

    
    debug_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    filter_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_1() called")

    name_value = container.get("name", None)
    label_value = container.get("label", None)
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.id"])
    my_geolocate_result_data = phantom.collect2(container=container, datapath=["my_geolocate:action_result.status","my_geolocate:action_result.data.*.country_name","my_geolocate:action_result.parameter.context.artifact_id"], action_results=results)

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]
    my_geolocate_result_item_0 = [item[0] for item in my_geolocate_result_data]
    my_geolocate_result_item_1 = [item[1] for item in my_geolocate_result_data]

    parameters = []

    parameters.append({
        "input_1": name_value,
        "input_2": label_value,
        "input_3": container_artifact_cef_item_0,
        "input_4": my_geolocate_result_item_0,
        "input_5": my_geolocate_result_item_1,
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
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="and",
        conditions=[
            ["filtered-data:filter_1:condition_1:my_geolocate:action_result.data.*.country_name", "!=", "United States"],
            ["filtered-data:filter_1:condition_1:my_geolocate:action_result.data.*.country_name", "!=", "Canada"],
            ["filtered-data:filter_1:condition_1:my_geolocate:action_result.data.*.country_name", "!=", "Germany"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        format_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    set_severity_to_low(action=action, success=success, container=container, results=results, handle=handle)

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

    phantom.set_label(container=container, label="lowsev")

    container = phantom.get_container(container.get('id', None))

    return


@phantom.playbook_block()
def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("prompt_1() called")

    # set user and message variables for phantom.prompt call

    user = None
    role = "Administrator"
    message = """The IPs in container {0} with severity {1} are not from our list of countries.\n\n{2}"""

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
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=1, name="prompt_1", parameters=parameters, response_types=response_types, callback=prompt_1_callback)

    return


@phantom.playbook_block()
def prompt_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("prompt_1_callback() called")

    
    decision_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    debug_4(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_1:action_result.summary.responses.0", "!=", "No"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        playbook_2025_jan_child_demo_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def debug_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_4() called")

    prompt_1_result_data = phantom.collect2(container=container, datapath=["prompt_1:action_result.status","prompt_1:action_result.summary.responses.0","prompt_1:action_result.parameter.message","prompt_1:action_result.parameter.context.artifact_id"], action_results=results)

    prompt_1_result_item_0 = [item[0] for item in prompt_1_result_data]
    prompt_1_summary_responses_0 = [item[1] for item in prompt_1_result_data]
    prompt_1_parameter_message = [item[2] for item in prompt_1_result_data]

    parameters = []

    parameters.append({
        "input_1": prompt_1_result_item_0,
        "input_2": prompt_1_summary_responses_0,
        "input_3": prompt_1_parameter_message,
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
            ["my_geolocate:action_result.data.*.country_name", "!=", None]
        ],
        name="filter_1:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        decision_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def list_merge_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("list_merge_5() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.cef.deviceAddress","artifact:*.cef.destinationAddress","artifact:*.id"])

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

    phantom.custom_function(custom_function="community/list_merge", parameters=parameters, name="list_merge_5", callback=my_geolocate)

    return


@phantom.playbook_block()
def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_1() called")

    template = """%%\nIP: {0} is from: {1}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_1:my_geolocate:action_result.parameter.ip",
        "filtered-data:filter_1:condition_1:my_geolocate:action_result.data.*.country_name"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    prompt_1(container=container)

    return


@phantom.playbook_block()
def playbook_2025_jan_child_demo_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_2025_jan_child_demo_1() called")

    filtered_result_0_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:my_geolocate:action_result.parameter.ip","filtered-data:filter_1:condition_1:my_geolocate:action_result.data.*.country_name"])
    prompt_1_result_data = phantom.collect2(container=container, datapath=["prompt_1:action_result.summary.responses.1"], action_results=results)

    filtered_result_0_parameter_ip = [item[0] for item in filtered_result_0_data_filter_1]
    filtered_result_0_data___country_name = [item[1] for item in filtered_result_0_data_filter_1]
    prompt_1_summary_responses_1 = [item[0] for item in prompt_1_result_data]

    inputs = {
        "ips": filtered_result_0_parameter_ip,
        "reason": prompt_1_summary_responses_1,
        "countries": filtered_result_0_data___country_name,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "Chris/2025 jan child demo", returns the playbook_run_id
    playbook_run_id = phantom.playbook("Chris/2025 jan child demo", container=container, name="playbook_2025_jan_child_demo_1", callback=decision_3, inputs=inputs)

    return


@phantom.playbook_block()
def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_3() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["playbook_2025_jan_child_demo_1:playbook_output:risk_score", ">=", 177]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        pin_7(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    pin_8(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def pin_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("pin_7() called")

    filtered_result_0_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:my_geolocate:action_result.parameter.ip","filtered-data:filter_1:condition_1:my_geolocate:action_result.data.*.country_name"])

    filtered_result_0_parameter_ip = [item[0] for item in filtered_result_0_data_filter_1]
    filtered_result_0_data___country_name = [item[1] for item in filtered_result_0_data_filter_1]

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
def pin_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("pin_8() called")

    playbook_2025_jan_child_demo_1_output_risk_score = phantom.collect2(container=container, datapath=["playbook_2025_jan_child_demo_1:playbook_output:risk_score"])
    playbook_2025_jan_child_demo_1_output_thoughts = phantom.collect2(container=container, datapath=["playbook_2025_jan_child_demo_1:playbook_output:thoughts"])

    playbook_2025_jan_child_demo_1_output_risk_score_values = [item[0] for item in playbook_2025_jan_child_demo_1_output_risk_score]
    playbook_2025_jan_child_demo_1_output_thoughts_values = [item[0] for item in playbook_2025_jan_child_demo_1_output_thoughts]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=playbook_2025_jan_child_demo_1_output_risk_score_values, message=playbook_2025_jan_child_demo_1_output_thoughts_values, pin_style="grey", pin_type="card")

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