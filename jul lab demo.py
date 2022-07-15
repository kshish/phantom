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
    decision_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


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
        logical_operator="and",
        conditions=[
            ["my_geo_locate_ip_that_chris_put_in:action_result.data.*.country_name", "!=", "United States"],
            ["my_geo_locate_ip_that_chris_put_in:action_result.data.*.country_name", "!=", "Brazil"],
            ["my_geo_locate_ip_that_chris_put_in:action_result.data.*.country_name", "!=", "Canada"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        prompt_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_1() called")

    # set user and message variables for phantom.prompt call

    user = "admin"
    message = """The container {0} has IP that is not from Friendlies list.\n\nIP: {1} is from {2}"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "my_geo_locate_ip_that_chris_put_in:action_result.parameter.ip",
        "my_geo_locate_ip_that_chris_put_in:action_result.data.*.country_name"
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_1", parameters=parameters)

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