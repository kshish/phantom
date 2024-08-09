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
def my_geo_locate(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("my_geo_locate() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # this action looks up an ip and returns public ip info
    ################################################################################

    list_merge_3__result = phantom.collect2(container=container, datapath=["list_merge_3:custom_function_result.data.item"])

    parameters = []

    # build parameters list for 'my_geo_locate' call
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

    phantom.act("geolocate ip", parameters=parameters, name="my_geo_locate", assets=["maxmind"], callback=my_geo_locate_callback)

    return


@phantom.playbook_block()
def my_geo_locate_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("my_geo_locate_callback() called")

    
    debug_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    filter_out_none(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_1() called")

    name_value = container.get("name", None)
    label_value = container.get("label", None)
    my_geo_locate_result_data = phantom.collect2(container=container, datapath=["my_geo_locate:action_result.status","my_geo_locate:action_result.message","my_geo_locate:action_result.data.*.country_name","my_geo_locate:action_result.parameter.ip","my_geo_locate:action_result.parameter.context.artifact_id"], action_results=results)
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.id"])

    my_geo_locate_result_item_0 = [item[0] for item in my_geo_locate_result_data]
    my_geo_locate_result_message = [item[1] for item in my_geo_locate_result_data]
    my_geo_locate_result_item_2 = [item[2] for item in my_geo_locate_result_data]
    my_geo_locate_parameter_ip = [item[3] for item in my_geo_locate_result_data]
    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]

    parameters = []

    parameters.append({
        "input_1": my_geo_locate_result_item_0,
        "input_2": my_geo_locate_result_message,
        "input_3": my_geo_locate_result_item_2,
        "input_4": container_artifact_cef_item_0,
        "input_5": my_geo_locate_parameter_ip,
        "input_6": name_value,
        "input_7": label_value,
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
def prompt_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("prompt_2() called")

    # set user and message variables for phantom.prompt call

    user = None
    role = "Administrator"
    message = """The container {0} with severity {1}\n\nIP is not in our list of countries.\n\n{2}"""

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

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=1, name="prompt_2", parameters=parameters, response_types=response_types, callback=decision_2, drop_none=False)

    return


@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_2:action_result.summary.responses.0", "!=", "No"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        playbook_aug_24_child_pb_demo_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def filter_out_none(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_out_none() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["my_geo_locate:action_result.data.*.country_name", "!=", ""]
        ],
        name="filter_out_none:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        in_or_out_of_list(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def list_merge_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("list_merge_3() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.destinationAddress","artifact:*.cef.sourceAddress","artifact:*.cef.deviceAddress","artifact:*.cef.mycef","artifact:*.id"])

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

    phantom.custom_function(custom_function="community/list_merge", parameters=parameters, name="list_merge_3", callback=my_geo_locate)

    return


@phantom.playbook_block()
def format_ip_and_country_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_ip_and_country_list() called")

    template = """%%\nIP: {0} is from: {1}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:in_or_out_of_list:condition_2:my_geo_locate:action_result.parameter.ip",
        "filtered-data:in_or_out_of_list:condition_2:my_geo_locate:action_result.data.*.country_name"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_ip_and_country_list")

    prompt_2(container=container)

    return


@phantom.playbook_block()
def playbook_aug_24_child_pb_demo_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_aug_24_child_pb_demo_1() called")

    filtered_result_0_data_filter_out_none = phantom.collect2(container=container, datapath=["filtered-data:filter_out_none:condition_1:my_geo_locate:action_result.parameter.ip","filtered-data:filter_out_none:condition_1:my_geo_locate:action_result.data.*.country_name"])
    prompt_2_result_data = phantom.collect2(container=container, datapath=["prompt_2:action_result.summary.responses.1"], action_results=results)

    filtered_result_0_parameter_ip = [item[0] for item in filtered_result_0_data_filter_out_none]
    filtered_result_0_data___country_name = [item[1] for item in filtered_result_0_data_filter_out_none]
    prompt_2_summary_responses_1 = [item[0] for item in prompt_2_result_data]

    inputs = {
        "ips": filtered_result_0_parameter_ip,
        "countries": filtered_result_0_data___country_name,
        "reason_for_high_severity": prompt_2_summary_responses_1,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "chris2/aug 24 child pb demo", returns the playbook_run_id
    playbook_run_id = phantom.playbook("chris2/aug 24 child pb demo", container=container, name="playbook_aug_24_child_pb_demo_1", callback=format_1, inputs=inputs)

    return


@phantom.playbook_block()
def add_comment_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_comment_4() called")

    format_1 = phantom.get_format_data(name="format_1")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_1)

    return


@phantom.playbook_block()
def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_1() called")

    template = """Risk score {0}\n"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_aug_24_child_pb_demo_1:playbook_output:risk_score"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    add_comment_4(container=container)

    return


@phantom.playbook_block()
def set_label_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_label_5() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_label(container=container, label="splunk")

    container = phantom.get_container(container.get('id', None))

    pin_2(container=container)

    return


@phantom.playbook_block()
def in_or_out_of_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("in_or_out_of_list() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filter_out_none:condition_1:my_geo_locate:action_result.data.*.country_name", "in", "custom_list:countries"]
        ],
        name="in_or_out_of_list:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        set_label_5(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filter_out_none:condition_1:my_geo_locate:action_result.data.*.country_name", "not in", "custom_list:countries"]
        ],
        name="in_or_out_of_list:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        format_ip_and_country_list(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def pin_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("pin_2() called")

    filtered_result_0_data_in_or_out_of_list = phantom.collect2(container=container, datapath=["filtered-data:in_or_out_of_list:condition_1:my_geo_locate:action_result.data.*.country_name","filtered-data:in_or_out_of_list:condition_1:my_geo_locate:action_result.parameter.ip"])

    filtered_result_0_data___country_name = [item[0] for item in filtered_result_0_data_in_or_out_of_list]
    filtered_result_0_parameter_ip = [item[1] for item in filtered_result_0_data_in_or_out_of_list]

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