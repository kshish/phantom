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
def you_geolocate(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("you_geolocate() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    list_merge_4__result = phantom.collect2(container=container, datapath=["list_merge_4:custom_function_result.data.item"])

    parameters = []

    # build parameters list for 'you_geolocate' call
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

    phantom.act("geolocate ip", parameters=parameters, name="you_geolocate", assets=["maxmind"], callback=you_geolocate_callback)

    return


@phantom.playbook_block()
def you_geolocate_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("you_geolocate_callback() called")

    
    debug_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    filter_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_1() called")

    name_value = container.get("name", None)
    label_value = container.get("label", None)
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.id"])
    you_geolocate_result_data = phantom.collect2(container=container, datapath=["you_geolocate:action_result.data.*.country_name","you_geolocate:action_result.parameter.ip","you_geolocate:action_result.parameter.context.artifact_id"], action_results=results)

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]
    you_geolocate_result_item_0 = [item[0] for item in you_geolocate_result_data]
    you_geolocate_parameter_ip = [item[1] for item in you_geolocate_result_data]

    parameters = []

    parameters.append({
        "input_1": container_artifact_cef_item_0,
        "input_2": name_value,
        "input_3": label_value,
        "input_4": you_geolocate_result_item_0,
        "input_5": you_geolocate_parameter_ip,
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
def set_low_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_low_severity() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_label(container=container, label="lowseverity")

    container = phantom.get_container(container.get('id', None))

    pin_6(container=container)

    return


@phantom.playbook_block()
def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("prompt_1() called")

    # set user and message variables for phantom.prompt call

    user = None
    role = "Administrator"
    message = """Hey!!!! The container {0} with {1} severity has IPs outside our list.\n\n{2}\n"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "container:severity",
        "format_1:formatted_data"
    ]

    # responses
    response_types = [
        {
            "prompt": "Would you like to change severity to High and do other things?",
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

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=1, name="prompt_1", parameters=parameters, response_types=response_types, callback=decision_2)

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
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        playbook_oct_2024_child_pb_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def list_merge_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("list_merge_4() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.destinationAddress","artifact:*.cef.sourceAddress","artifact:*.cef.chrisField","artifact:*.cef.deviceAddress","artifact:*.id"])

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]
    container_artifact_cef_item_1 = [item[1] for item in container_artifact_data]
    container_artifact_cef_item_2 = [item[2] for item in container_artifact_data]
    container_artifact_cef_item_3 = [item[3] for item in container_artifact_data]

    parameters = []

    parameters.append({
        "input_1": container_artifact_cef_item_0,
        "input_2": container_artifact_cef_item_1,
        "input_3": container_artifact_cef_item_2,
        "input_4": container_artifact_cef_item_3,
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

    phantom.custom_function(custom_function="community/list_merge", parameters=parameters, name="list_merge_4", callback=you_geolocate)

    return


@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_1() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["you_geolocate:action_result.data.*.country_name", "!=", ""]
        ],
        name="filter_1:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        sort_countries(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_1() called")

    template = """%%\nIP is: {0} is from: {1}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:sort_countries:condition_2:you_geolocate:action_result.parameter.ip",
        "filtered-data:sort_countries:condition_2:you_geolocate:action_result.data.*.country_name"
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
def playbook_oct_2024_child_pb_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_oct_2024_child_pb_1() called")

    prompt_1_result_data = phantom.collect2(container=container, datapath=["prompt_1:action_result.summary.responses.1"], action_results=results)
    filtered_result_0_data_sort_countries = phantom.collect2(container=container, datapath=["filtered-data:sort_countries:condition_2:you_geolocate:action_result.parameter.ip","filtered-data:sort_countries:condition_2:you_geolocate:action_result.data.*.country_name"])

    prompt_1_summary_responses_1 = [item[0] for item in prompt_1_result_data]
    filtered_result_0_parameter_ip = [item[0] for item in filtered_result_0_data_sort_countries]
    filtered_result_0_data___country_name = [item[1] for item in filtered_result_0_data_sort_countries]

    inputs = {
        "reason_for_high_severity": prompt_1_summary_responses_1,
        "ips": filtered_result_0_parameter_ip,
        "countries": filtered_result_0_data___country_name,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "chris/oct 2024 child pb", returns the playbook_run_id
    playbook_run_id = phantom.playbook("chris/oct 2024 child pb", container=container, name="playbook_oct_2024_child_pb_1", callback=pin_5, inputs=inputs)

    return


@phantom.playbook_block()
def pin_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("pin_5() called")

    playbook_oct_2024_child_pb_1_output_risk_score = phantom.collect2(container=container, datapath=["playbook_oct_2024_child_pb_1:playbook_output:risk_score"])

    playbook_oct_2024_child_pb_1_output_risk_score_values = [item[0] for item in playbook_oct_2024_child_pb_1_output_risk_score]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=playbook_oct_2024_child_pb_1_output_risk_score_values, message="Risk Score", pin_style="grey", pin_type="card")

    return


@phantom.playbook_block()
def call_api_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("call_api_3() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return


@phantom.playbook_block()
def sort_countries(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("sort_countries() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filter_1:condition_1:you_geolocate:action_result.data.*.country_name", "in", "custom_list:countries"]
        ],
        name="sort_countries:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        set_low_severity(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filter_1:condition_1:you_geolocate:action_result.data.*.country_name", "not in", "custom_list:countries"]
        ],
        name="sort_countries:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        format_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def pin_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("pin_6() called")

    filtered_result_0_data_sort_countries = phantom.collect2(container=container, datapath=["filtered-data:sort_countries:condition_1:you_geolocate:action_result.data.*.country_name"])

    filtered_result_0_data___country_name = [item[0] for item in filtered_result_0_data_sort_countries]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=filtered_result_0_data___country_name, message="IPs in our list", pin_style="blue", pin_type="card")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return