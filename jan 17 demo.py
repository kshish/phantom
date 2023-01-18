"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'list_merge_5' block
    list_merge_5(container=container)

    return

def geolocator(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("geolocator() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    list_merge_5_data = phantom.collect2(container=container, datapath=["list_merge_5:custom_function_result.data.*.item"])

    parameters = []

    # build parameters list for 'geolocator' call
    for list_merge_5_data_item in list_merge_5_data:
        if list_merge_5_data_item[0] is not None:
            parameters.append({
                "ip": list_merge_5_data_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("geolocate ip", parameters=parameters, name="geolocator", assets=["maxmind"], callback=geolocator_callback)

    return


def geolocator_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("geolocator_callback() called")

    
    debug_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    filter_out_none(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("debug_1() called")

    owner_name_value = container.get("owner_name", None)
    role_value = container.get("role", None)
    mygeolocate_result_data = phantom.collect2(container=container, datapath=["mygeolocate:action_result.data.*.country_name","mygeolocate:action_result.status","mygeolocate:action_result.message","mygeolocate:action_result.parameter.context.artifact_id"], action_results=results)

    mygeolocate_result_item_0 = [item[0] for item in mygeolocate_result_data]
    mygeolocate_result_item_1 = [item[1] for item in mygeolocate_result_data]
    mygeolocate_result_message = [item[2] for item in mygeolocate_result_data]

    parameters = []

    parameters.append({
        "input_1": mygeolocate_result_item_0,
        "input_2": mygeolocate_result_item_1,
        "input_3": mygeolocate_result_message,
        "input_4": owner_name_value,
        "input_5": role_value,
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


def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_1() called")

    # set user and message variables for phantom.prompt call

    user = "Administrator"
    message = """The event: {0} has IP(s) outside of our list.  \n<br>\n{1}"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
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
            "prompt": "What message would you like on the HUD card",
            "options": {
                "type": "message",
            },
        }
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=1, name="prompt_1", parameters=parameters, response_types=response_types, callback=decision_3)

    return


def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_3() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_1:action_result.summary.responses.0", "==", "No"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        return

    # check for 'else' condition 2
    playbook_jan_18_child_demo_1(action=action, success=success, container=container, results=results, handle=handle)

    return


def set_low_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_low_severity() called")

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


def list_merge_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("list_merge_5() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.destinationAddress","artifact:*.cef.sourceAddress","artifact:*.id"])

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

    phantom.custom_function(custom_function="community/list_merge", parameters=parameters, name="list_merge_5", callback=geolocator)

    return


def filter_out_none(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_out_none() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["geolocator:action_result.data.*.country_name", "==", ""]
        ],
        name="filter_out_none:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        pin_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["geolocator:action_result.data.*.country_name", "in", "custom_list:countries"]
        ],
        name="filter_out_none:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        pin_11(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids and results for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        conditions=[
            ["geolocator:action_result.data.*.country_name", "not in", "custom_list:countries"]
        ],
        name="filter_out_none:condition_3")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        pin_12(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    return


def format_ip_and_country_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_ip_and_country_list() called")

    template = """%%\nIP: {0} is from: {1}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_out_none:condition_1:geolocator:action_result.parameter.ip",
        "filtered-data:filter_out_none:condition_1:geolocator:action_result.data.*.country_name"
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


def playbook_jan_18_child_demo_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_jan_18_child_demo_1() called")

    prompt_1_result_data = phantom.collect2(container=container, datapath=["prompt_1:action_result.summary.responses.1"], action_results=results)
    geolocator_result_data = phantom.collect2(container=container, datapath=["geolocator:action_result.parameter.ip"], action_results=results)

    prompt_1_summary_responses_1 = [item[0] for item in prompt_1_result_data]
    geolocator_parameter_ip = [item[0] for item in geolocator_result_data]

    inputs = {
        "msg": prompt_1_summary_responses_1,
        "myip": geolocator_parameter_ip,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "chris/jan 18 child demo", returns the playbook_run_id
    playbook_run_id = phantom.playbook("chris/jan 18 child demo", container=container, name="playbook_jan_18_child_demo_1", callback=decision_1, inputs=inputs)

    return


def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["playbook_jan_18_child_demo_1:playbook_output:riskscore", ">", 80]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        add_comment_4(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        conditions=[
            ["playbook_jan_18_child_demo_1:playbook_output:riskscore", ">", 60]
        ])

    # call connected blocks if condition 2 matched
    if found_match_2:
        set_sensitivity_8(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 3
    found_match_3 = phantom.decision(
        container=container,
        conditions=[
            ["playbook_jan_18_child_demo_1:playbook_output:riskscore", ">", 40]
        ])

    # call connected blocks if condition 3 matched
    if found_match_3:
        set_sensitivity_9(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 4
    set_sensitivity_6(action=action, success=success, container=container, results=results, handle=handle)

    return


def add_comment_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_4() called")

    playbook_jan_18_child_demo_1_output_reason = phantom.collect2(container=container, datapath=["playbook_jan_18_child_demo_1:playbook_output:reason"])

    playbook_jan_18_child_demo_1_output_reason_values = [item[0] for item in playbook_jan_18_child_demo_1_output_reason]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=playbook_jan_18_child_demo_1_output_reason_values)

    set_sensitivity_7(container=container)

    return


def set_sensitivity_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_sensitivity_6() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_sensitivity(container=container, sensitivity="white")

    container = phantom.get_container(container.get('id', None))

    return


def set_sensitivity_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_sensitivity_7() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_sensitivity(container=container, sensitivity="red")

    container = phantom.get_container(container.get('id', None))

    return


def set_sensitivity_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_sensitivity_8() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_sensitivity(container=container, sensitivity="amber")

    container = phantom.get_container(container.get('id', None))

    set_label_10(container=container)

    return


def set_sensitivity_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_sensitivity_9() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_sensitivity(container=container, sensitivity="green")

    container = phantom.get_container(container.get('id', None))

    return


def set_label_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_label_10() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_label(container=container, label="tier-1")

    container = phantom.get_container(container.get('id', None))

    return


def pin_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pin_2() called")

    filtered_result_0_data_filter_out_none = phantom.collect2(container=container, datapath=["filtered-data:filter_out_none:condition_1:geolocator:action_result.parameter.ip"])

    filtered_result_0_parameter_ip = [item[0] for item in filtered_result_0_data_filter_out_none]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=filtered_result_0_parameter_ip, message="Internal IP(s)", pin_style="grey", pin_type="card")

    return


def pin_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pin_11() called")

    filtered_result_0_data_filter_out_none = phantom.collect2(container=container, datapath=["filtered-data:filter_out_none:condition_2:geolocator:action_result.data.*.country_name"])

    filtered_result_0_data___country_name = [item[0] for item in filtered_result_0_data_filter_out_none]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=filtered_result_0_data___country_name, message="IP(s) in our list", pin_style="blue", pin_type="card")

    return


def pin_12(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pin_12() called")

    filtered_result_0_data_filter_out_none = phantom.collect2(container=container, datapath=["filtered-data:filter_out_none:condition_3:geolocator:action_result.data.*.country_name"])

    filtered_result_0_data___country_name = [item[0] for item in filtered_result_0_data_filter_out_none]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=filtered_result_0_data___country_name, message="IP(s) not in our list")

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    summary_json = phantom.get_summary()
    if 'result' in summary_json:
        for action_result in summary_json['result']:
            if 'action_run_id' in action_result:
                action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                phantom.debug(action_results)

    ################################################################################
    ## Custom Code End
    ################################################################################

    return