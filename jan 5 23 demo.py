"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'my_geolocate' block
    my_geolocate(container=container)
    # call 'whois_domain_1' block
    whois_domain_1(container=container)

    return

def my_geolocate(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("my_geolocate() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

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

    phantom.act("geolocate ip", parameters=parameters, name="my_geolocate", assets=["maxmind"], callback=join_decision_1)

    return


def whois_domain_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("whois_domain_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceDnsDomain","artifact:*.id"])

    parameters = []

    # build parameters list for 'whois_domain_1' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "domain": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("whois domain", parameters=parameters, name="whois_domain_1", assets=["whois"], callback=join_decision_1)

    return


def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("debug_1() called")

    name_value = container.get("name", None)
    label_value = container.get("label", None)
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.destinationAddress","artifact:*.id"])
    whois_domain_1_result_data = phantom.collect2(container=container, datapath=["whois_domain_1:action_result.data.*.status","whois_domain_1:action_result.parameter.context.artifact_id"], action_results=results)
    my_geolocate_result_data = phantom.collect2(container=container, datapath=["my_geolocate:action_result.data.*.country_name","my_geolocate:action_result.parameter.context.artifact_id"], action_results=results)

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]
    whois_domain_1_result_item_0 = [item[0] for item in whois_domain_1_result_data]
    my_geolocate_result_item_0 = [item[0] for item in my_geolocate_result_data]

    parameters = []

    parameters.append({
        "input_1": "Chris wuz here",
        "input_2": name_value,
        "input_3": label_value,
        "input_4": container_artifact_cef_item_0,
        "input_5": whois_domain_1_result_item_0,
        "input_6": my_geolocate_result_item_0,
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


def join_decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_decision_1() called")

    if phantom.completed(action_names=["my_geolocate", "whois_domain_1"]):
        # call connected block "decision_1"
        decision_1(container=container, handle=handle)

    return


def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="or",
        conditions=[
            ["my_geolocate:action_result.data.*.country_name", "==", "United States"],
            ["my_geolocate:action_result.data.*.country_name", "==", "Canada"],
            ["my_geolocate:action_result.data.*.country_name", "==", "Mexico"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        set_severity_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    prompt_for_severity_set_to_high(action=action, success=success, container=container, results=results, handle=handle)

    return


def set_severity_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_severity_2() called")

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


def prompt_for_severity_set_to_high(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_for_severity_set_to_high() called")

    # set user and message variables for phantom.prompt call

    user = "Administrator"
    message = """The event {0} has IP(s) off continent.\n\nIP: {1} is from: {2}"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=1, name="prompt_for_severity_set_to_high", parameters=parameters, response_types=response_types, callback=decision_2)

    return


def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_for_severity_set_to_high:action_result.summary.responses.0", "==", "Yes"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        set_severity_3(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def set_severity_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_severity_3() called")

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