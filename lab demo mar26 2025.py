"""
This will be a comment in the python script
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'list_merge_10' block
    list_merge_10(container=container)

    return

@phantom.playbook_block()
def my_geolocate_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("my_geolocate_ip() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    list_merge_10__result = phantom.collect2(container=container, datapath=["list_merge_10:custom_function_result.data.item"])

    parameters = []

    # build parameters list for 'my_geolocate_ip' call
    for list_merge_10__result_item in list_merge_10__result:
        if list_merge_10__result_item[0] is not None:
            parameters.append({
                "ip": list_merge_10__result_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("geolocate ip", parameters=parameters, name="my_geolocate_ip", assets=["maxmind"], callback=my_geolocate_ip_callback)

    return


@phantom.playbook_block()
def my_geolocate_ip_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("my_geolocate_ip_callback() called")

    
    debug_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    filter_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_1() called")

    name_value = container.get("name", None)
    label_value = container.get("label", None)
    my_geolocate_ip_result_data = phantom.collect2(container=container, datapath=["my_geolocate_ip:action_result.data.*.country_name","my_geolocate_ip:action_result.parameter.ip","my_geolocate_ip:action_result.data.*.latitude","my_geolocate_ip:action_result.parameter.context.artifact_id"], action_results=results)
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.deviceAddress","artifact:*.id"])

    my_geolocate_ip_result_item_0 = [item[0] for item in my_geolocate_ip_result_data]
    my_geolocate_ip_parameter_ip = [item[1] for item in my_geolocate_ip_result_data]
    my_geolocate_ip_result_item_2 = [item[2] for item in my_geolocate_ip_result_data]
    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]

    parameters = []

    parameters.append({
        "input_1": my_geolocate_ip_result_item_0,
        "input_2": my_geolocate_ip_parameter_ip,
        "input_3": my_geolocate_ip_result_item_2,
        "input_4": container_artifact_cef_item_0,
        "input_5": name_value,
        "input_6": label_value,
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
            ["filtered-data:filter_1:condition_1:my_geolocate_ip:action_result.data.*.country_name", "!=", "United States"],
            ["filtered-data:filter_1:condition_1:my_geolocate_ip:action_result.data.*.country_name", "!=", "Canada"],
            ["filtered-data:filter_1:condition_1:my_geolocate_ip:action_result.data.*.country_name", "!=", "Mexico"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        return

    # check for 'else' condition 2
    set_severity_to_low(action=action, success=success, container=container, results=results, handle=handle)
    format_ip_and_country_list(action=action, success=success, container=container, results=results, handle=handle)

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

    pin_9(container=container)

    return


@phantom.playbook_block()
def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("prompt_1() called")

    # set user and message variables for phantom.prompt call

    user = None
    role = "Administrator"
    message = """The container {0} with severity {1} has IPs from outside our list.\n\n{2}"""

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
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=1, name="prompt_1", parameters=parameters, response_types=response_types, callback=prompt_1_callback)

    return


@phantom.playbook_block()
def prompt_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("prompt_1_callback() called")

    
    decision_3(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    debug_3(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_3() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_1:action_result.summary.responses.0", "!=", "No"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        set_severity_to_highg(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def debug_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_3() called")

    prompt_1_result_data = phantom.collect2(container=container, datapath=["prompt_1:action_result.summary.responses.0","prompt_1:action_result.status","prompt_1:action_result.parameter.message","prompt_1:action_result.parameter.context.artifact_id"], action_results=results)
    my_geolocate_ip_result_data = phantom.collect2(container=container, datapath=["my_geolocate_ip:action_result.data.*.couxntry_iso_code.subfieldlist.*.subfield","my_geolocate_ip:action_result.parameter.context.artifact_id"], action_results=results)

    prompt_1_summary_responses_0 = [item[0] for item in prompt_1_result_data]
    prompt_1_result_item_1 = [item[1] for item in prompt_1_result_data]
    prompt_1_parameter_message = [item[2] for item in prompt_1_result_data]
    my_geolocate_ip_result_item_0 = [item[0] for item in my_geolocate_ip_result_data]

    parameters = []

    parameters.append({
        "input_1": prompt_1_summary_responses_0,
        "input_2": prompt_1_result_item_1,
        "input_3": prompt_1_parameter_message,
        "input_4": my_geolocate_ip_result_item_0,
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
def set_severity_to_highg(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_severity_to_highg() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_severity(container=container, severity="high")

    container = phantom.get_container(container.get('id', None))

    pin_8(container=container)

    return


@phantom.playbook_block()
def pin_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("pin_8() called")

    my_geolocate_ip_result_data = phantom.collect2(container=container, datapath=["my_geolocate_ip:action_result.data.*.country_name"], action_results=results)

    my_geolocate_ip_result_item_0 = [item[0] for item in my_geolocate_ip_result_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=my_geolocate_ip_result_item_0, message="IPs not in our list", pin_style="red", pin_type="card")

    return


@phantom.playbook_block()
def pin_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("pin_9() called")

    my_geolocate_ip_result_data = phantom.collect2(container=container, datapath=["my_geolocate_ip:action_result.data.*.country_name"], action_results=results)

    my_geolocate_ip_result_item_0 = [item[0] for item in my_geolocate_ip_result_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=my_geolocate_ip_result_item_0, message="IPs in our list", pin_style="blue", pin_type="card")

    return


@phantom.playbook_block()
def list_merge_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("list_merge_10() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.cef.deviceAddress","artifact:*.cef.destinationAddress","artifact:*.cef.app","artifact:*.id"])

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

    phantom.custom_function(custom_function="community/list_merge", parameters=parameters, name="list_merge_10", callback=my_geolocate_ip)

    return


@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_1() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["my_geolocate_ip:action_result.data.*.country_name", "!=", ""]
        ],
        name="filter_1:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        decision_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def format_ip_and_country_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_ip_and_country_list() called")

    template = """IP: {0} is from: {1}\n"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_1:my_geolocate_ip:action_result.parameter.ip",
        "filtered-data:filter_1:condition_1:my_geolocate_ip:action_result.data.*.country_name"
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
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################
    phantom.debug("chris wuz here")
    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return