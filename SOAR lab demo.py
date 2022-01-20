"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'my_geolocate' block
    my_geolocate(container=container)

    return

def my_geolocate(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("my_geolocate() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # This is a demo
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

    phantom.act("geolocate ip", parameters=parameters, name="my_geolocate", assets=["maxmind"], callback=filtered_out_none)

    return


def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_4() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["filtered-data:filtered_out_none:condition_1:my_geolocate:action_result.data.*.country_name", "!=", "United States"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        format_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def ask_to_change_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("ask_to_change_severity() called")

    # set user and message variables for phantom.prompt call

    user = "admin"
    message = """The container {0} with severity {1}\n\n{2}\n"""

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
            "prompt": "Please pick a color",
            "options": {
                "type": "range",
                "min": 50,
                "max": 1000,
            },
        }
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=1, name="ask_to_change_severity", parameters=parameters, response_types=response_types, callback=decision_5)

    return


def decision_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_5() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["ask_to_change_severity:action_result.summary.responses.0", "!=", "No"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        set_severity_2(action=action, success=success, container=container, results=results, handle=handle)
        return

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

    phantom.set_severity(container=container, severity="high")

    container = phantom.get_container(container.get('id', None))

    return


def filtered_out_none(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filtered_out_none() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["my_geolocate:action_result.data.*.country_name", "!=", ""]
        ],
        name="filtered_out_none:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        decision_4(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        filter_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_1() called")

    template = """%%\nThe ip {0} is from {1}\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filtered_out_none:condition_1:my_geolocate:action_result.parameter.ip",
        "filtered-data:filtered_out_none:condition_1:my_geolocate:action_result.data.*.country_name"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    ask_to_change_severity(container=container)

    return


def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_2() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filtered_out_none:condition_1:my_geolocate:action_result.data.*.country_name", "==", "United States"]
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        pin_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filtered_out_none:condition_1:my_geolocate:action_result.data.*.country_name", "!=", "United States"]
        ],
        name="filter_2:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        outside_countries(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


def pin_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pin_1() called")

    filtered_result_0_data_filter_2 = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_1:my_geolocate:action_result.parameter.ip"])

    filtered_result_0_parameter_ip = [item[0] for item in filtered_result_0_data_filter_2]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=filtered_result_0_parameter_ip, message="One or more IPs in US", pin_style="blue", pin_type="card")

    return


def pin_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pin_3() called")

    outside_ips = phantom.get_format_data(name="outside_ips")
    outside_countries = phantom.get_format_data(name="outside_countries")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=outside_ips, message=outside_countries, pin_style="red", pin_type="card")

    return


def outside_countries(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("outside_countries() called")

    template = """%%\n{0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_2:condition_2:my_geolocate:action_result.data.*.country_name"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="outside_countries")

    outside_ips(container=container)

    return


def outside_ips(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("outside_ips() called")

    template = """%%\n{0}\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_2:condition_2:my_geolocate:action_result.parameter.ip"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="outside_ips")

    pin_3(container=container)

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