"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'my_geolocate' block
    my_geolocate(container=container)
    # call 'lookup_ip_1' block
    lookup_ip_1(container=container)

    return

@phantom.playbook_block()
def my_geolocate(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("my_geolocate() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # This block retrieves public IP addr info
    ################################################################################

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.id"])

    parameters = []

    # build parameters list for 'my_geolocate' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "ip": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
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

    
    join_debug_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    decision_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def lookup_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("lookup_ip_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.id"])

    parameters = []

    # build parameters list for 'lookup_ip_1' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "ip": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("lookup ip", parameters=parameters, name="lookup_ip_1", assets=["google_dns"], callback=join_debug_1)

    return


@phantom.playbook_block()
def join_debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("join_debug_1() called")

    if phantom.completed(action_names=["my_geolocate", "lookup_ip_1"]):
        # call connected block "debug_1"
        debug_1(container=container, handle=handle)

    return


@phantom.playbook_block()
def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_1() called")

    name_value = container.get("name", None)
    label_value = container.get("label", None)
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.id"])
    my_geolocate_result_data = phantom.collect2(container=container, datapath=["my_geolocate:action_result.data.*.country_name","my_geolocate:action_result.data.*.state_name","my_geolocate:action_result.parameter.context.artifact_id"], action_results=results)
    lookup_ip_1_result_data = phantom.collect2(container=container, datapath=["lookup_ip_1:action_result.summary.hostname","lookup_ip_1:action_result.parameter.context.artifact_id"], action_results=results)

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]
    my_geolocate_result_item_0 = [item[0] for item in my_geolocate_result_data]
    my_geolocate_result_item_1 = [item[1] for item in my_geolocate_result_data]
    lookup_ip_1_summary_hostname = [item[0] for item in lookup_ip_1_result_data]

    parameters = []

    parameters.append({
        "input_1": name_value,
        "input_2": label_value,
        "input_3": container_artifact_cef_item_0,
        "input_4": my_geolocate_result_item_0,
        "input_5": my_geolocate_result_item_1,
        "input_6": lookup_ip_1_summary_hostname,
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
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="or",
        conditions=[
            ["my_geolocate:action_result.data.*.country_name", "==", "United States"],
            ["my_geolocate:action_result.data.*.country_name", "==", "Italy"],
            ["my_geolocate:action_result.data.*.country_name", "==", "Denmark"],
            ["my_geolocate:action_result.data.*.country_name", "==", "Brazil"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        set_severity_to_low(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    prompt_1(action=action, success=success, container=container, results=results, handle=handle)

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

    return


@phantom.playbook_block()
def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("prompt_1() called")

    # set user and message variables for phantom.prompt call

    user = None
    role = "Administrator"
    message = """The container {0} with severity {1} has IP(s) outside our list of countries.\n\nIP: {2} is from {3}"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "container:severity",
        "my_geolocate:action_result.parameter.ip",
        "my_geolocate:action_result.data.*.country_name"
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

    
    decision_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    debug_5(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="or",
        conditions=[
            ["prompt_1:action_result.summary.responses.0", "==", "Yes"],
            ["prompt_1:action_result.status", "==", "Failed"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        set_severity_to_high(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def set_severity_to_high(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_severity_to_high() called")

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
def debug_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_5() called")

    prompt_1_result_data = phantom.collect2(container=container, datapath=["prompt_1:action_result.status","prompt_1:action_result.parameter.context.artifact_id"], action_results=results)

    prompt_1_result_item_0 = [item[0] for item in prompt_1_result_data]

    parameters = []

    parameters.append({
        "input_1": prompt_1_result_item_0,
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

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_5")

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