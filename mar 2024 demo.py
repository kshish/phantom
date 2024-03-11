"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'geolocate_ip_1' block
    geolocate_ip_1(container=container)

    return

@phantom.playbook_block()
def geolocate_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("geolocate_ip_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.id"])

    parameters = []

    # build parameters list for 'geolocate_ip_1' call
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

    phantom.act("geolocate ip", parameters=parameters, name="geolocate_ip_1", assets=["maxmind"], callback=geolocate_ip_1_callback)

    return


@phantom.playbook_block()
def geolocate_ip_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("geolocate_ip_1_callback() called")

    
    debug_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    decision_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("debug_1() called")

    name_value = container.get("name", None)
    label_value = container.get("label", None)
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.id"])
    geolocate_ip_1_result_data = phantom.collect2(container=container, datapath=["geolocate_ip_1:action_result.data.*.country_name","geolocate_ip_1:action_result.data.*.city_name","geolocate_ip_1:action_result.parameter.context.artifact_id"], action_results=results)
    launching_user_data = phantom.collect2(container=container, datapath=["playbook:launching_user.name"])

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]
    geolocate_ip_1_result_item_0 = [item[0] for item in geolocate_ip_1_result_data]
    geolocate_ip_1_result_item_1 = [item[1] for item in geolocate_ip_1_result_data]
    launching_user__name = launching_user_data[0][0]

    parameters = []

    parameters.append({
        "input_1": name_value,
        "input_2": label_value,
        "input_3": container_artifact_cef_item_0,
        "input_4": geolocate_ip_1_result_item_0,
        "input_5": geolocate_ip_1_result_item_1,
        "input_6": launching_user__name,
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
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="or",
        conditions=[
            ["geolocate_ip_1:action_result.data.*.country_name", "==", "United States"],
            ["geolocate_ip_1:action_result.data.*.country_name", "==", "Canada"],
            ["geolocate_ip_1:action_result.data.*.country_name", "==", "Mexico"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        set_low_severity(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    prompt_1(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
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


@phantom.playbook_block()
def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_1() called")

    # set user and message variables for phantom.prompt call

    user = None
    role = "Administrator"
    message = """The container {0} with severity {1} has the following:\n\nIP: {2} is from: {3}"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "container:severity",
        "geolocate_ip_1:action_result.parameter.ip",
        "geolocate_ip_1:action_result.data.*.country_name"
    ]

    # responses
    response_types = [
        {
            "prompt": "Would you like to change severity to high",
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
def prompt_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_1_callback() called")

    
    decision_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    debug_3(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="and",
        conditions=[
            ["prompt_1:action_result.status", "==", "success"],
            ["prompt_1:action_result.summary.responses.0", "==", "Yes"]
        ],
        case_sensitive=True,
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        set_high_severity(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def debug_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("debug_3() called")

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

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_3")

    return


@phantom.playbook_block()
def set_high_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
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