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

def my_geolocate(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("my_geolocate() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    list_merge_5_data = phantom.collect2(container=container, datapath=["list_merge_5:custom_function_result.data.*.item"])

    parameters = []

    # build parameters list for 'my_geolocate' call
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

    phantom.act("geolocate ip", parameters=parameters, name="my_geolocate", assets=["maxmind"], callback=external_ips)

    return


def decide_if_in_friendlies(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decide_if_in_friendlies() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="and",
        conditions=[
            ["filtered-data:filter_1:condition_1:my_geolocate:action_result.data.*.country_name", "!=", "United States"],
            ["filtered-data:filter_1:condition_1:my_geolocate:action_result.data.*.country_name", "!=", "Australia"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        return

    # check for 'else' condition 2
    set_severity_to_low(action=action, success=success, container=container, results=results, handle=handle)
    format_ip_and_country_list(action=action, success=success, container=container, results=results, handle=handle)

    return


def set_severity_to_low(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
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


def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_1() called")

    # set user and message variables for phantom.prompt call

    user = "admin"
    message = """The container {0} with severity {1} IPs are outside of US and AUS\n\n{2}\n"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "container:severity",
        "format_ip_and_country_list:formatted_data"
    ]

    # responses
    response_types = [
        {
            "prompt": "Would you like to promote to case",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        },
        {
            "prompt": "Please provide an email address",
            "options": {
                "type": "message",
            },
        },
        {
            "prompt": "Please add a comment",
            "options": {
                "type": "message",
            },
        }
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=1, name="prompt_1", parameters=parameters, response_types=response_types, callback=decide_on_prompt_response)

    return


def decide_on_prompt_response(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decide_on_prompt_response() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_1:action_result.summary.responses.0", "!=", "No"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        playbook_woolies_child_pb_demo_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def external_ips(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("external_ips() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["my_geolocate:action_result.data.*.country_name", "!=", ""]
        ],
        name="external_ips:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        decide_if_in_friendlies(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


def format_ip_and_country_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_ip_and_country_list() called")

    template = """%%\nIP: {0} is from {1}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:external_ips:condition_1:my_geolocate:action_result.parameter.ip",
        "filtered-data:external_ips:condition_1:my_geolocate:action_result.data.*.country_name"
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


def list_merge_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("list_merge_5() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.cef.destinationAddress","artifact:*.cef.myField","artifact:*.id"])

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

    phantom.custom_function(custom_function="community/list_merge", parameters=parameters, name="list_merge_5", callback=my_geolocate)

    return


def playbook_woolies_child_pb_demo_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_woolies_child_pb_demo_1() called")

    prompt_1_result_data = phantom.collect2(container=container, datapath=["prompt_1:action_result.summary.responses.1","prompt_1:action_result.summary.responses.2"], action_results=results)
    format_ip_and_country_list = phantom.get_format_data(name="format_ip_and_country_list")

    prompt_1_summary_responses_1 = [item[0] for item in prompt_1_result_data]
    prompt_1_summary_responses_2 = [item[1] for item in prompt_1_result_data]

    inputs = {
        "emailaddress": prompt_1_summary_responses_1,
        "commentfromanalyst": prompt_1_summary_responses_2,
        "ipandcountrylist": format_ip_and_country_list,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "chris/Woolies child pb demo", returns the playbook_run_id
    playbook_run_id = phantom.playbook("chris/Woolies child pb demo", container=container, name="playbook_woolies_child_pb_demo_1", callback=pin_6, inputs=inputs)

    return


def pin_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pin_6() called")

    playbook_woolies_child_pb_demo_1_output_emailstatus = phantom.collect2(container=container, datapath=["playbook_woolies_child_pb_demo_1:playbook_output:emailstatus"])
    playbook_woolies_child_pb_demo_1_output_responsefromchild = phantom.collect2(container=container, datapath=["playbook_woolies_child_pb_demo_1:playbook_output:responsefromchild"])

    playbook_woolies_child_pb_demo_1_output_emailstatus_values = [item[0] for item in playbook_woolies_child_pb_demo_1_output_emailstatus]
    playbook_woolies_child_pb_demo_1_output_responsefromchild_values = [item[0] for item in playbook_woolies_child_pb_demo_1_output_responsefromchild]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=playbook_woolies_child_pb_demo_1_output_emailstatus_values, message=playbook_woolies_child_pb_demo_1_output_responsefromchild_values, pin_style="grey", pin_type="card")

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")
    phantom.debug("Chris wuz here")
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