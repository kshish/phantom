"""

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
def geolocate_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("geolocate_ip_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    list_merge_6__result = phantom.collect2(container=container, datapath=["list_merge_6:custom_function_result.data.item"])

    parameters = []

    # build parameters list for 'geolocate_ip_1' call
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

    phantom.act("geolocate ip", parameters=parameters, name="geolocate_ip_1", assets=["maxmind"], callback=geolocate_ip_1_callback)

    return


@phantom.playbook_block()
def geolocate_ip_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("geolocate_ip_1_callback() called")

    
    debug_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    filter_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_1() called")

    name_value = container.get("name", None)
    label_value = container.get("label", None)
    geolocate_ip_1_result_data = phantom.collect2(container=container, datapath=["geolocate_ip_1:action_result.status","geolocate_ip_1:action_result.data.*.country_iso_code","geolocate_ip_1:action_result.data.*.country_name","geolocate_ip_1:action_result.parameter.context.artifact_id"], action_results=results)

    geolocate_ip_1_result_item_0 = [item[0] for item in geolocate_ip_1_result_data]
    geolocate_ip_1_result_item_1 = [item[1] for item in geolocate_ip_1_result_data]
    geolocate_ip_1_result_item_2 = [item[2] for item in geolocate_ip_1_result_data]

    parameters = []

    parameters.append({
        "input_1": geolocate_ip_1_result_item_0,
        "input_2": geolocate_ip_1_result_item_1,
        "input_3": geolocate_ip_1_result_item_2,
        "input_4": name_value,
        "input_5": label_value,
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
def decide_if_ips_are_in_our_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decide_if_ips_are_in_our_list() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="and",
        conditions=[
            ["filtered-data:filter_1:condition_1:geolocate_ip_1:action_result.data.*.country_iso_code", "!=", "US"],
            ["filtered-data:filter_1:condition_1:geolocate_ip_1:action_result.data.*.country_iso_code", "!=", "SA"],
            ["filtered-data:filter_1:condition_1:geolocate_ip_1:action_result.data.*.country_iso_code", "!=", "CA"]
        ],
        conditions_dps=[
            ["filtered-data:filter_1:condition_1:geolocate_ip_1:action_result.data.*.country_iso_code", "!=", "US"],
            ["filtered-data:filter_1:condition_1:geolocate_ip_1:action_result.data.*.country_iso_code", "!=", "SA"],
            ["filtered-data:filter_1:condition_1:geolocate_ip_1:action_result.data.*.country_iso_code", "!=", "CA"]
        ],
        name="decide_if_ips_are_in_our_list:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        prompt_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    set_low_severity(action=action, success=success, container=container, results=results, handle=handle)

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

    phantom.set_severity(container=container, severity="low")

    container = phantom.get_container(container.get('id', None))

    return


@phantom.playbook_block()
def set_high_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_high_severity() called")

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
    message = """The {0} incident with severity {1} has IP(s) outside of our list of countries.\n\nIP: {2} is from {3} (ISO code: {4})"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "container:severity",
        "geolocate_ip_1:action_result.parameter.ip",
        "geolocate_ip_1:action_result.data.*.country_name",
        "geolocate_ip_1:action_result.data.*.country_iso_code"
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

    
    decide_on_prompt_response(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    debug_prompt_response(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def decide_on_prompt_response(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decide_on_prompt_response() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_1:action_result.summary.responses.0", "==", "YES"]
        ],
        conditions_dps=[
            ["prompt_1:action_result.summary.responses.0", "==", "YES"]
        ],
        name="decide_on_prompt_response:condition_1",
        case_sensitive=False,
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        set_high_severity(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def debug_prompt_response(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_prompt_response() called")

    prompt_1_result_data = phantom.collect2(container=container, datapath=["prompt_1:action_result.status","prompt_1:action_result.summary.responses.0","prompt_1:action_result.parameter.context.artifact_id"], action_results=results)
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.act.someother","artifact:*.id"])
    geolocate_ip_1_result_data = phantom.collect2(container=container, datapath=["geolocate_ip_1:action_result.data","geolocate_ip_1:action_result.parameter.context.artifact_id"], action_results=results)

    prompt_1_result_item_0 = [item[0] for item in prompt_1_result_data]
    prompt_1_summary_responses_0 = [item[1] for item in prompt_1_result_data]
    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]
    geolocate_ip_1_result_item_0 = [item[0] for item in geolocate_ip_1_result_data]

    parameters = []

    parameters.append({
        "input_1": prompt_1_result_item_0,
        "input_2": prompt_1_summary_responses_0,
        "input_3": ["Users are slow"],
        "input_4": container_artifact_cef_item_0,
        "input_5": geolocate_ip_1_result_item_0,
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

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_prompt_response")

    return


@phantom.playbook_block()
def lookup_domain_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("lookup_domain_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    parameters.append({
        "domain": "",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("lookup domain", parameters=parameters, name="lookup_domain_1", assets=["google_dns"])

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

    phantom.custom_function(custom_function="community/list_merge", parameters=parameters, name="list_merge_6", callback=geolocate_ip_1)

    return


@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_1() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["geolocate_ip_1:action_result.data.*.country_iso_code", "!=", None]
        ],
        conditions_dps=[
            ["geolocate_ip_1:action_result.data.*.country_iso_code", "!=", None]
        ],
        name="filter_1:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        decide_if_ips_are_in_our_list(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

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