"""
This s a comment.\n\nThis playbook is for blah blah demo blah bla\n\n
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'list_merge_6' block
    list_merge_6(container=container)

    return

@phantom.playbook_block()
def my_geo_locate_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("my_geo_locate_ip() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    list_merge_6__result = phantom.collect2(container=container, datapath=["list_merge_6:custom_function_result.data.item"])

    parameters = []

    # build parameters list for 'my_geo_locate_ip' call
    for list_merge_6__result_item in list_merge_6__result:
        if list_merge_6__result_item[0] is not None:
            parameters.append({
                "ip": list_merge_6__result_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("geolocate ip", parameters=parameters, name="my_geo_locate_ip", assets=["maxmind"], callback=my_geo_locate_ip_callback)

    return


@phantom.playbook_block()
def my_geo_locate_ip_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("my_geo_locate_ip_callback() called")

    
    debug_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    filter_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_1() called")

    name_value = container.get("name", None)
    label_value = container.get("label", None)
    my_geo_locate_ip_result_data = phantom.collect2(container=container, datapath=["my_geo_locate_ip:action_result.data.*.country_iso_code","my_geo_locate_ip:action_result.data.*.country_name","my_geo_locate_ip:action_result.parameter.ip","my_geo_locate_ip:action_result.data","my_geo_locate_ip:action_result.parameter.context.artifact_id"], action_results=results)

    my_geo_locate_ip_result_item_0 = [item[0] for item in my_geo_locate_ip_result_data]
    my_geo_locate_ip_result_item_1 = [item[1] for item in my_geo_locate_ip_result_data]
    my_geo_locate_ip_parameter_ip = [item[2] for item in my_geo_locate_ip_result_data]
    my_geo_locate_ip_result_item_3 = [item[3] for item in my_geo_locate_ip_result_data]

    parameters = []

    parameters.append({
        "input_1": my_geo_locate_ip_result_item_0,
        "input_2": my_geo_locate_ip_result_item_1,
        "input_3": name_value,
        "input_4": label_value,
        "input_5": my_geo_locate_ip_parameter_ip,
        "input_6": my_geo_locate_ip_result_item_3,
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
def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_3() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="and",
        conditions=[
            ["filtered-data:filter_1:condition_1:my_geo_locate_ip:action_result.data.*.country_iso_code", "!=", "US"],
            ["filtered-data:filter_1:condition_1:my_geo_locate_ip:action_result.data.*.country_iso_code", "!=", "DE"],
            ["filtered-data:filter_1:condition_1:my_geo_locate_ip:action_result.data.*.country_iso_code", "!=", "SA"],
            ["filtered-data:filter_1:condition_1:my_geo_locate_ip:action_result.data.*.country_iso_code", "!=", "CA"],
            ["filtered-data:filter_1:condition_1:my_geo_locate_ip:action_result.data.*.country_iso_code", "!=", "MX"]
        ],
        conditions_dps=[
            ["filtered-data:filter_1:condition_1:my_geo_locate_ip:action_result.data.*.country_iso_code", "!=", "US"],
            ["filtered-data:filter_1:condition_1:my_geo_locate_ip:action_result.data.*.country_iso_code", "!=", "DE"],
            ["filtered-data:filter_1:condition_1:my_geo_locate_ip:action_result.data.*.country_iso_code", "!=", "SA"],
            ["filtered-data:filter_1:condition_1:my_geo_locate_ip:action_result.data.*.country_iso_code", "!=", "CA"],
            ["filtered-data:filter_1:condition_1:my_geo_locate_ip:action_result.data.*.country_iso_code", "!=", "MX"]
        ],
        name="decision_3:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        return

    # check for 'else' condition 2
    set_sev_low(action=action, success=success, container=container, results=results, handle=handle)
    format_3(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def set_sev_low(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_sev_low() called")

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


@phantom.playbook_block()
def set_sev_high(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_sev_high() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_severity(container=container, severity="high")

    container = phantom.get_container(container.get('id', None))

    return


@phantom.playbook_block()
def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("prompt_1() called")

    # set approver and message variables for phantom.prompt call

    user = None
    role = "Administrator"
    message = """Container: {0} with severity {1}\n\nIP is not in our list of countries.\n\n{2}"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "container:severity",
        "format_3:formatted_data"
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
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=1, name="prompt_1", parameters=parameters, response_types=response_types, callback=prompt_1_callback)

    return


@phantom.playbook_block()
def prompt_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("prompt_1_callback() called")

    
    decide_what_the_response_was(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    debug_4(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def decide_what_the_response_was(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decide_what_the_response_was() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_1:action_result.summary.responses.0", "!=", "No"]
        ],
        conditions_dps=[
            ["prompt_1:action_result.summary.responses.0", "!=", "No"]
        ],
        name="decide_what_the_response_was:condition_1",
        case_sensitive=True,
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        set_sev_high(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def debug_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_4() called")

    prompt_1_result_data = phantom.collect2(container=container, datapath=["prompt_1:action_result.summary.responses.0","prompt_1:action_result.status","prompt_1:action_result.parameter.context.artifact_id"], action_results=results)

    prompt_1_summary_responses_0 = [item[0] for item in prompt_1_result_data]
    prompt_1_result_item_1 = [item[1] for item in prompt_1_result_data]

    parameters = []

    parameters.append({
        "input_1": prompt_1_summary_responses_0,
        "input_2": prompt_1_result_item_1,
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
def list_merge_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("list_merge_6() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.destinationAddress","artifact:*.cef.deviceAddress","artifact:*.cef.sourceAddress","artifact:*.id"])

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

    phantom.custom_function(custom_function="community/list_merge", parameters=parameters, name="list_merge_6", callback=my_geo_locate_ip)

    return


@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_1() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["my_geo_locate_ip:action_result.data.*.country_iso_code", "!=", None]
        ],
        conditions_dps=[
            ["my_geo_locate_ip:action_result.data.*.country_iso_code", "!=", None]
        ],
        name="filter_1:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        decision_3(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def format_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_3() called")

    template = """IP: {0} is from: {1} (ISO Code: {2})\n"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_1:my_geo_locate_ip:action_result.parameter.ip",
        "filtered-data:filter_1:condition_1:my_geo_locate_ip:action_result.data.*.country_name",
        "filtered-data:filter_1:condition_1:my_geo_locate_ip:action_result.data.*.country_iso_code"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_3")

    prompt_1(container=container)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################
    phantom.debug("Chris wuz here")
    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return