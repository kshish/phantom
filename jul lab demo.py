"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'list_merge_2' block
    list_merge_2(container=container)

    return

def my_geo_locate_ip_that_chris_put_in(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("my_geo_locate_ip_that_chris_put_in() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    list_merge_2_data = phantom.collect2(container=container, datapath=["list_merge_2:custom_function_result.data.*.item"])

    parameters = []

    # build parameters list for 'my_geo_locate_ip_that_chris_put_in' call
    for list_merge_2_data_item in list_merge_2_data:
        if list_merge_2_data_item[0] is not None:
            parameters.append({
                "ip": list_merge_2_data_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("geolocate ip", parameters=parameters, name="my_geo_locate_ip_that_chris_put_in", assets=["maxmind"], callback=my_geo_locate_ip_that_chris_put_in_callback)

    return


def my_geo_locate_ip_that_chris_put_in_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("my_geo_locate_ip_that_chris_put_in_callback() called")

    
    debug_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    geolocate_filtered_in_public(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("debug_1() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.id"])
    my_geo_locate_ip_that_chris_put_in_result_data = phantom.collect2(container=container, datapath=["my_geo_locate_ip_that_chris_put_in:action_result.data.*.country_name","my_geo_locate_ip_that_chris_put_in:action_result.data.*.latitude","my_geo_locate_ip_that_chris_put_in:action_result.data.*.longitude","my_geo_locate_ip_that_chris_put_in:action_result.data.*.postal_code","my_geo_locate_ip_that_chris_put_in:action_result.parameter.ip","my_geo_locate_ip_that_chris_put_in:action_result.parameter.context.artifact_id"], action_results=results)

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]
    my_geo_locate_ip_that_chris_put_in_result_item_0 = [item[0] for item in my_geo_locate_ip_that_chris_put_in_result_data]
    my_geo_locate_ip_that_chris_put_in_result_item_1 = [item[1] for item in my_geo_locate_ip_that_chris_put_in_result_data]
    my_geo_locate_ip_that_chris_put_in_result_item_2 = [item[2] for item in my_geo_locate_ip_that_chris_put_in_result_data]
    my_geo_locate_ip_that_chris_put_in_result_item_3 = [item[3] for item in my_geo_locate_ip_that_chris_put_in_result_data]
    my_geo_locate_ip_that_chris_put_in_parameter_ip = [item[4] for item in my_geo_locate_ip_that_chris_put_in_result_data]

    parameters = []

    parameters.append({
        "input_1": container_artifact_cef_item_0,
        "input_2": my_geo_locate_ip_that_chris_put_in_result_item_0,
        "input_3": my_geo_locate_ip_that_chris_put_in_result_item_1,
        "input_4": my_geo_locate_ip_that_chris_put_in_result_item_2,
        "input_5": my_geo_locate_ip_that_chris_put_in_result_item_3,
        "input_6": my_geo_locate_ip_that_chris_put_in_parameter_ip,
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


def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["filtered-data:geolocate_filtered_in_public:condition_1:my_geo_locate_ip_that_chris_put_in:action_result.data.*.country_name", "not in", "custom_list:countries"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        format_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_1() called")

    # set user and message variables for phantom.prompt call

    user = "admin"
    message = """The container {0} has IP that is not from Friendlies list.\n\n{1}\n"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "format_1:formatted_data.*"
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
            "prompt": "enter a number",
            "options": {
                "type": "range",
                "min": 1,
                "max": 100,
            },
        }
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=1, name="prompt_1", parameters=parameters, response_types=response_types, callback=decision_2)

    return


def list_merge_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("list_merge_2() called")

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

    phantom.custom_function(custom_function="community/list_merge", parameters=parameters, name="list_merge_2", callback=my_geo_locate_ip_that_chris_put_in)

    return


def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_1() called")

    template = """%%\nIP: {0} is from {1}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:geolocate_filtered_in_public:condition_1:my_geo_locate_ip_that_chris_put_in:action_result.parameter.ip",
        "filtered-data:geolocate_filtered_in_public:condition_1:my_geo_locate_ip_that_chris_put_in:action_result.data.*.country_name"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    prompt_1(container=container)

    return


def geolocate_filtered_in_public(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("geolocate_filtered_in_public() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["my_geo_locate_ip_that_chris_put_in:action_result.data.*.country_name", "!=", None]
        ],
        name="geolocate_filtered_in_public:condition_1",
        case_sensitive=True)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        decision_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_1:action_result.summary.responses.0", "!=", "No"]
        ],
        case_sensitive=False)

    # call connected blocks if condition 1 matched
    if found_match_1:
        playbook_jul_child_pb_1(action=action, success=success, container=container, results=results, handle=handle)
        set_label_3(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def playbook_jul_child_pb_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_jul_child_pb_1() called")

    prompt_1_result_data = phantom.collect2(container=container, datapath=["prompt_1:action_result.summary.responses.1"], action_results=results)
    my_geo_locate_ip_that_chris_put_in_result_data = phantom.collect2(container=container, datapath=["my_geo_locate_ip_that_chris_put_in:action_result.parameter.ip"], action_results=results)
    filtered_result_0_data_geolocate_filtered_in_public = phantom.collect2(container=container, datapath=["filtered-data:geolocate_filtered_in_public:condition_1:my_geo_locate_ip_that_chris_put_in:action_result.data"])

    prompt_1_summary_responses_1 = [item[0] for item in prompt_1_result_data]
    my_geo_locate_ip_that_chris_put_in_parameter_ip = [item[0] for item in my_geo_locate_ip_that_chris_put_in_result_data]
    filtered_result_0_data = [item[0] for item in filtered_result_0_data_geolocate_filtered_in_public]

    inputs = {
        "hud_msg": prompt_1_summary_responses_1,
        "some_ip": my_geo_locate_ip_that_chris_put_in_parameter_ip,
        "filtered_geolocate_list": filtered_result_0_data,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "chris/jul child pb", returns the playbook_run_id
    playbook_run_id = phantom.playbook("chris/jul child pb", container=container, name="playbook_jul_child_pb_1", callback=pin_4, inputs=inputs)

    return


def pin_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pin_4() called")

    playbook_jul_child_pb_1_output_awesomeness_number_from_childpb = phantom.collect2(container=container, datapath=["playbook_jul_child_pb_1:playbook_output:awesomeness_number_from_childpb"])

    playbook_jul_child_pb_1_output_awesomeness_number_from_childpb_values = [item[0] for item in playbook_jul_child_pb_1_output_awesomeness_number_from_childpb]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=playbook_jul_child_pb_1_output_awesomeness_number_from_childpb_values, message=playbook_jul_child_pb_1_output_awesomeness_number_from_childpb_values, pin_style="red", pin_type="card")

    return


def set_label_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_label_3() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_label(container=container, label="splunk")

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

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    ################################################################################
    ## Custom Code End
    ################################################################################

    return