"""

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
def my_geolocate(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
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
    phantom.debug(parameters)
    phantom.debug("chris wuz here")
    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("geolocate ip", parameters=parameters, name="my_geolocate", assets=["maxmind"], callback=my_geolocate_callback)

    return


@phantom.playbook_block()
def my_geolocate_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("my_geolocate_callback() called")

    
    debug_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    filter_in_external_ip(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("debug_1() called")

    name_value = container.get("name", None)
    label_value = container.get("label", None)
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.id"])
    my_geolocate_result_data = phantom.collect2(container=container, datapath=["my_geolocate:action_result.data.*.country_name","my_geolocate:action_result.data.*.continent_name","my_geolocate:action_result.parameter.context.artifact_id"], action_results=results)

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]
    my_geolocate_result_item_0 = [item[0] for item in my_geolocate_result_data]
    my_geolocate_result_item_1 = [item[1] for item in my_geolocate_result_data]

    parameters = []

    parameters.append({
        "input_1": container_artifact_cef_item_0,
        "input_2": name_value,
        "input_3": label_value,
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
def create_pin(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("create_pin() called")

    filtered_result_0_data_filter_in_and_out_from_list = phantom.collect2(container=container, datapath=["filtered-data:filter_in_and_out_from_list:condition_1:my_geolocate:action_result.data.*.country_name"])

    filtered_result_0_data___country_name = [item[0] for item in filtered_result_0_data_filter_in_and_out_from_list]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=filtered_result_0_data___country_name, message="IPs inside our list", pin_style="blue", pin_type="card")

    container = phantom.get_container(container.get('id', None))

    return


@phantom.playbook_block()
def prompt_for_high_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_for_high_severity() called")

    # set user and message variables for phantom.prompt call

    user = None
    role = "Administrator"
    message = """The event {0} with severity {1} has IP(s) outside our list.\n\n\n{2}"""

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

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=1, name="prompt_for_high_severity", parameters=parameters, response_types=response_types, callback=prompt_for_high_severity_callback, drop_none=False)

    return


@phantom.playbook_block()
def prompt_for_high_severity_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_for_high_severity_callback() called")

    
    decision_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    debug_3(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_for_high_severity:action_result.summary.responses.0", "!=", "No"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        playbook_jluy2023_child_pb_demo_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def debug_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("debug_3() called")

    prompt_for_high_severity_result_data = phantom.collect2(container=container, datapath=["prompt_for_high_severity:action_result.status","prompt_for_high_severity:action_result.parameter.message","prompt_for_high_severity:action_result.summary.responses.0","prompt_for_high_severity:action_result.parameter.context.artifact_id"], action_results=results)

    prompt_for_high_severity_result_item_0 = [item[0] for item in prompt_for_high_severity_result_data]
    prompt_for_high_severity_parameter_message = [item[1] for item in prompt_for_high_severity_result_data]
    prompt_for_high_severity_summary_responses_0 = [item[2] for item in prompt_for_high_severity_result_data]

    parameters = []

    parameters.append({
        "input_1": prompt_for_high_severity_result_item_0,
        "input_2": prompt_for_high_severity_parameter_message,
        "input_3": prompt_for_high_severity_summary_responses_0,
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
def filter_in_external_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_in_external_ip() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["my_geolocate:action_result.data.*.country_name", "!=", ""]
        ],
        name="filter_in_external_ip:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_in_and_out_from_list(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def list_merge_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("list_merge_5() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.cef.destinationAddress","artifact:*.id"])

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

    phantom.custom_function(custom_function="community/list_merge", parameters=parameters, name="list_merge_5", callback=my_geolocate)

    return


@phantom.playbook_block()
def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_1() called")

    template = """%%\nIP: {0} is from {1}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_in_external_ip:condition_1:my_geolocate:action_result.parameter.ip",
        "filtered-data:filter_in_external_ip:condition_1:my_geolocate:action_result.data.*.country_name"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    prompt_for_high_severity(container=container)

    return


@phantom.playbook_block()
def playbook_jluy2023_child_pb_demo_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_jluy2023_child_pb_demo_1() called")

    filtered_result_0_data_filter_in_and_out_from_list = phantom.collect2(container=container, datapath=["filtered-data:filter_in_and_out_from_list:condition_2:my_geolocate:action_result.parameter.ip","filtered-data:filter_in_and_out_from_list:condition_2:my_geolocate:action_result.data.*.country_name"])
    prompt_for_high_severity_result_data = phantom.collect2(container=container, datapath=["prompt_for_high_severity:action_result.summary.responses.1"], action_results=results)

    filtered_result_0_parameter_ip = [item[0] for item in filtered_result_0_data_filter_in_and_out_from_list]
    filtered_result_0_data___country_name = [item[1] for item in filtered_result_0_data_filter_in_and_out_from_list]
    prompt_for_high_severity_summary_responses_1 = [item[0] for item in prompt_for_high_severity_result_data]

    inputs = {
        "ips": filtered_result_0_parameter_ip,
        "countries": filtered_result_0_data___country_name,
        "reason_for_high_severity": prompt_for_high_severity_summary_responses_1,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "Chris/jluy2023 child pb demo", returns the playbook_run_id
    playbook_run_id = phantom.playbook("Chris/jluy2023 child pb demo", container=container, name="playbook_jluy2023_child_pb_demo_1", callback=add_note_9, inputs=inputs)

    return


@phantom.playbook_block()
def add_note_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_note_9() called")

    playbook_jluy2023_child_pb_demo_1_output_their_thoughts = phantom.collect2(container=container, datapath=["playbook_jluy2023_child_pb_demo_1:playbook_output:their_thoughts"])

    playbook_jluy2023_child_pb_demo_1_output_their_thoughts_values = [item[0] for item in playbook_jluy2023_child_pb_demo_1_output_their_thoughts]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=playbook_jluy2023_child_pb_demo_1_output_their_thoughts_values, note_format="markdown", note_type="general", title="Note from Child PB")

    return


@phantom.playbook_block()
def filter_in_and_out_from_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_in_and_out_from_list() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filter_in_external_ip:condition_1:my_geolocate:action_result.data.*.country_name", "in", "custom_list:countries"]
        ],
        name="filter_in_and_out_from_list:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        create_pin(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filter_in_external_ip:condition_1:my_geolocate:action_result.data.*.country_name", "not in", "custom_list:countries"]
        ],
        name="filter_in_and_out_from_list:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        format_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

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