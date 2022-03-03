"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'my_ip_list' block
    my_ip_list(container=container)

    return

def locate_source(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("locate_source() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    my_ip_list_data = phantom.collect2(container=container, datapath=["my_ip_list:custom_function_result.data.*.item"])

    parameters = []

    # build parameters list for 'locate_source' call
    for my_ip_list_data_item in my_ip_list_data:
        if my_ip_list_data_item[0] is not None:
            parameters.append({
                "ip": my_ip_list_data_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("geolocate ip", parameters=parameters, name="locate_source", assets=["maxmind"], callback=filter_out_none)

    return


def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("debug_1() called")

    owner_name_value = container.get("owner_name", None)
    label_value = container.get("label", None)
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.destinationAddress","artifact:*.id"])
    locate_source_result_data = phantom.collect2(container=container, datapath=["locate_source:action_result.data","locate_source:action_result.parameter.context.artifact_id"], action_results=results)

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]
    locate_source_result_item_0 = [item[0] for item in locate_source_result_data]

    parameters = []

    parameters.append({
        "input_1": "chris wuz here",
        "input_2": owner_name_value,
        "input_3": label_value,
        "input_4": container_artifact_cef_item_0,
        "input_5": locate_source_result_item_0,
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

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_1", callback=decision_2)

    return


def my_ip_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("my_ip_list() called")

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

    phantom.custom_function(custom_function="community/list_merge", parameters=parameters, name="my_ip_list", callback=locate_source)

    return


def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["filtered-data:filter_out_none:condition_1:locate_source:action_result.data.*.country_name", "!=", "United States"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        format_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    pin_4(action=action, success=success, container=container, results=results, handle=handle)

    return


def pin_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pin_4() called")

    filtered_result_0_data_filter_out_none = phantom.collect2(container=container, datapath=["filtered-data:filter_out_none:condition_1:locate_source:action_result.parameter.ip"])

    filtered_result_0_parameter_ip = [item[0] for item in filtered_result_0_data_filter_out_none]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=filtered_result_0_parameter_ip, message="IP is from USA", pin_style="blue", pin_type="card")

    return


def prompt_for_high_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_for_high_severity() called")

    # set user and message variables for phantom.prompt call

    user = "admin"
    message = """The container {0} \n\n{1}"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "format_1:formatted_data"
    ]

    # responses
    response_types = [
        {
            "prompt": "Do you want to change severity to High?",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=1, name="prompt_for_high_severity", parameters=parameters, response_types=response_types, callback=decision_3)

    return


def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_3() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_for_high_severity:action_result.summary.responses.0", "!=", "No"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        playbook_demo_child_pb_promote_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def filter_out_none(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_out_none() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["locate_source:action_result.data.*.country_name", "!=", ""]
        ],
        name="filter_out_none:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        debug_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["locate_source:action_result.data.*.country_name", "==", ""]
        ],
        name="filter_out_none:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        pass

    return


def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_1() called")

    template = """%%\nip: {0} is from {1}\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_out_none:condition_1:locate_source:action_result.parameter.ip",
        "filtered-data:filter_out_none:condition_1:locate_source:action_result.data.*.country_name"
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


def playbook_demo_child_pb_promote_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_demo_child_pb_promote_1() called")

    filtered_result_0_data_filter_out_none = phantom.collect2(container=container, datapath=["filtered-data:filter_out_none:condition_1:locate_source:action_result.parameter.ip","filtered-data:filter_out_none:condition_1:locate_source:action_result.data","filtered-data:filter_out_none:condition_1:locate_source:action_result.data.*.country_name"])

    filtered_result_0_parameter_ip = [item[0] for item in filtered_result_0_data_filter_out_none]
    filtered_result_0_data = [item[1] for item in filtered_result_0_data_filter_out_none]
    filtered_result_0_data___country_name = [item[2] for item in filtered_result_0_data_filter_out_none]

    inputs = {
        "myip": filtered_result_0_parameter_ip,
        "a_list": filtered_result_0_data,
        "country_name": filtered_result_0_data___country_name,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "chris/demo child pb promote", returns the playbook_run_id
    playbook_run_id = phantom.playbook("chris/demo child pb promote", container=container, name="playbook_demo_child_pb_promote_1", callback=prompt_2, inputs=inputs)

    return


def prompt_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_2() called")

    # set user and message variables for phantom.prompt call

    user = "admin"
    message = """response from child {0}\nsecond thought{1}"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_demo_child_pb_promote_1:playbook_output:a_message",
        "playbook_demo_child_pb_promote_1:playbook_output:thought"
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_2", parameters=parameters)

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