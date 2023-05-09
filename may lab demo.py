"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'merge_ips' block
    merge_ips(container=container)

    return

@phantom.playbook_block()
def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("debug_1() called")

    geolocate_ip_1_result_data = phantom.collect2(container=container, datapath=["geolocate_ip_1:action_result.data.*.country_name","geolocate_ip_1:action_result.parameter.ip","geolocate_ip_1:action_result.parameter.context.artifact_id"], action_results=results)

    geolocate_ip_1_result_item_0 = [item[0] for item in geolocate_ip_1_result_data]
    geolocate_ip_1_parameter_ip = [item[1] for item in geolocate_ip_1_result_data]

    parameters = []

    parameters.append({
        "input_1": geolocate_ip_1_result_item_0,
        "input_2": geolocate_ip_1_parameter_ip,
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

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_1", callback=debug_2)

    return


@phantom.playbook_block()
def debug_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("debug_2() called")

    my_geolocate_result_data = phantom.collect2(container=container, datapath=["my_geolocate:action_result.data.*.longitude","my_geolocate:action_result.parameter.context.artifact_id"], action_results=results)

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

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_2")

    return


@phantom.playbook_block()
def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_1() called")

    # set user and message variables for phantom.prompt call

    user = None
    role = "Administrator"
    message = """At least one of the IPs is outside of our countries list.\n\n{0} with severity {1} has the following IP(s) and countries.\n\n{2}"""

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
            "prompt": "Reason for High Severity",
            "options": {
                "type": "message",
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=1, name="prompt_1", parameters=parameters, response_types=response_types, callback=decision_2)

    return


@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_1:action_result.summary.responses.0", "!=", "No"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        playbook_may_2023_child_demo_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def rows_with_countrys(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("rows_with_countrys() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["geolocate_ip_1:action_result.data.*.country_name", "!=", ""]
        ],
        name="rows_with_countrys:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def merge_ips(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("merge_ips() called")

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

    phantom.custom_function(custom_function="community/list_merge", parameters=parameters, name="merge_ips", callback=geolocate_ip_1)

    return


@phantom.playbook_block()
def geolocate_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("geolocate_ip_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    merge_ips_data = phantom.collect2(container=container, datapath=["merge_ips:custom_function_result.data.*.item"])

    parameters = []

    # build parameters list for 'geolocate_ip_1' call
    for merge_ips_data_item in merge_ips_data:
        if merge_ips_data_item[0] is not None:
            parameters.append({
                "ip": merge_ips_data_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("geolocate ip", parameters=parameters, name="geolocate_ip_1", assets=["maxmind"], callback=geolocate_ip_1_callback)

    return


@phantom.playbook_block()
def geolocate_ip_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("geolocate_ip_1_callback() called")

    
    debug_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    rows_with_countrys(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def playbook_may_2023_child_demo_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_may_2023_child_demo_1() called")

    geolocate_ip_1_result_data = phantom.collect2(container=container, datapath=["geolocate_ip_1:action_result.parameter.ip","geolocate_ip_1:action_result.data.*.country_name"], action_results=results)
    prompt_1_result_data = phantom.collect2(container=container, datapath=["prompt_1:action_result.summary.responses.1"], action_results=results)

    geolocate_ip_1_parameter_ip = [item[0] for item in geolocate_ip_1_result_data]
    geolocate_ip_1_result_item_1 = [item[1] for item in geolocate_ip_1_result_data]
    prompt_1_summary_responses_1 = [item[0] for item in prompt_1_result_data]

    inputs = {
        "ips": geolocate_ip_1_parameter_ip,
        "reason": prompt_1_summary_responses_1,
        "countries": geolocate_ip_1_result_item_1,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "utils/may 2023 child demo", returns the playbook_run_id
    playbook_run_id = phantom.playbook("utils/may 2023 child demo", container=container, name="playbook_may_2023_child_demo_1", callback=pin_5, inputs=inputs)

    return


@phantom.playbook_block()
def pin_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pin_5() called")

    playbook_may_2023_child_demo_1_output_some_ip = phantom.collect2(container=container, datapath=["playbook_may_2023_child_demo_1:playbook_output:some_ip"])
    playbook_may_2023_child_demo_1_output_thoughts = phantom.collect2(container=container, datapath=["playbook_may_2023_child_demo_1:playbook_output:thoughts"])

    playbook_may_2023_child_demo_1_output_some_ip_values = [item[0] for item in playbook_may_2023_child_demo_1_output_some_ip]
    playbook_may_2023_child_demo_1_output_thoughts_values = [item[0] for item in playbook_may_2023_child_demo_1_output_thoughts]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=playbook_may_2023_child_demo_1_output_some_ip_values, message=playbook_may_2023_child_demo_1_output_thoughts_values, pin_style="red", pin_type="card")

    geolocate_ip_2(container=container)

    return


@phantom.playbook_block()
def geolocate_ip_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("geolocate_ip_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    playbook_may_2023_child_demo_1_output_some_ip = phantom.collect2(container=container, datapath=["playbook_may_2023_child_demo_1:playbook_output:some_ip"])

    parameters = []

    # build parameters list for 'geolocate_ip_2' call
    for playbook_may_2023_child_demo_1_output_some_ip_item in playbook_may_2023_child_demo_1_output_some_ip:
        if playbook_may_2023_child_demo_1_output_some_ip_item[0] is not None:
            parameters.append({
                "ip": playbook_may_2023_child_demo_1_output_some_ip_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("geolocate ip", parameters=parameters, name="geolocate_ip_2", assets=["maxmind"], callback=pin_6)

    return


@phantom.playbook_block()
def pin_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pin_6() called")

    geolocate_ip_2_result_data = phantom.collect2(container=container, datapath=["geolocate_ip_2:action_result.data.*.country_name"], action_results=results)
    playbook_may_2023_child_demo_1_output_some_ip = phantom.collect2(container=container, datapath=["playbook_may_2023_child_demo_1:playbook_output:some_ip"])

    geolocate_ip_2_result_item_0 = [item[0] for item in geolocate_ip_2_result_data]
    playbook_may_2023_child_demo_1_output_some_ip_values = [item[0] for item in playbook_may_2023_child_demo_1_output_some_ip]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=geolocate_ip_2_result_item_0, message=playbook_may_2023_child_demo_1_output_some_ip_values, pin_style="blue", pin_type="card")

    return


@phantom.playbook_block()
def set_label_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_label_8() called")

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


@phantom.playbook_block()
def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_2() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:rows_with_countrys:condition_1:geolocate_ip_1:action_result.data.*.country_name", "in", "custom_list:countries"]
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        pin_3(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:rows_with_countrys:condition_1:geolocate_ip_1:action_result.data.*.country_name", "not in", "custom_list:countries"]
        ],
        name="filter_2:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        pin_4(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def pin_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pin_3() called")

    filtered_result_0_data_filter_2 = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_1:geolocate_ip_1:action_result.data.*.country_name"])

    filtered_result_0_data___country_name = [item[0] for item in filtered_result_0_data_filter_2]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=filtered_result_0_data___country_name, message="in our list", pin_style="blue", pin_type="card")

    return


@phantom.playbook_block()
def pin_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pin_4() called")

    filtered_result_0_data_filter_2 = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_2:geolocate_ip_1:action_result.data.*.country_name"])

    filtered_result_0_data___country_name = [item[0] for item in filtered_result_0_data_filter_2]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=filtered_result_0_data___country_name, message="Not in our List", pin_style="red", pin_type="card")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################
    phantom.debug(container)
    phantom.debug(summary)
    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return