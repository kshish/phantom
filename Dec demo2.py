"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'list_merge_7' block
    list_merge_7(container=container)

    return

def my_geo(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("my_geo() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    list_merge_7_data = phantom.collect2(container=container, datapath=["list_merge_7:custom_function_result.data.*.item"])

    parameters = []

    # build parameters list for 'my_geo' call
    for list_merge_7_data_item in list_merge_7_data:
        if list_merge_7_data_item[0] is not None:
            parameters.append({
                "ip": list_merge_7_data_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("geolocate ip", parameters=parameters, name="my_geo", assets=["maxmind"], callback=my_geo_callback)

    return


def my_geo_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("my_geo_callback() called")

    
    debug_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    filter_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("debug_1() called")

    my_geo_result_data = phantom.collect2(container=container, datapath=["my_geo:action_result.data.*.country_iso_code","my_geo:action_result.data.*.country_name","my_geo:action_result.parameter.context.artifact_id"], action_results=results)
    my_lookup_ip_result_data = phantom.collect2(container=container, datapath=["my_lookup_ip:action_result.status","my_lookup_ip:action_result.parameter.context.artifact_id"], action_results=results)
    whois_ip_1_result_data = phantom.collect2(container=container, datapath=["whois_ip_1:action_result.status","whois_ip_1:action_result.message","whois_ip_1:action_result.parameter.context.artifact_id"], action_results=results)

    my_geo_result_item_0 = [item[0] for item in my_geo_result_data]
    my_geo_result_item_1 = [item[1] for item in my_geo_result_data]
    my_lookup_ip_result_item_0 = [item[0] for item in my_lookup_ip_result_data]
    whois_ip_1_result_item_0 = [item[0] for item in whois_ip_1_result_data]
    whois_ip_1_result_message = [item[1] for item in whois_ip_1_result_data]

    parameters = []

    parameters.append({
        "input_1": my_geo_result_item_0,
        "input_2": my_geo_result_item_1,
        "input_3": my_lookup_ip_result_item_0,
        "input_4": whois_ip_1_result_item_0,
        "input_5": whois_ip_1_result_message,
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


def list_merge_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("list_merge_7() called")

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

    phantom.custom_function(custom_function="community/list_merge", parameters=parameters, name="list_merge_7", callback=my_geo)

    return


def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_2() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["my_geo:action_result.data.*.country_name", "in", "custom_list:some list"]
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        pin_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["my_geo:action_result.data.*.country_name", "not in", "custom_list:some list"]
        ],
        name="filter_2:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        pin_3(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids and results for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        logical_operator="or",
        conditions=[
            ["my_geo:action_result.data.*.country_name", "==", None],
            ["my_geo:action_result.parameter.ip", "==", "127.0.0.1"]
        ],
        name="filter_2:condition_3")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        pass

    return


def pin_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pin_2() called")

    my_geo_result_data = phantom.collect2(container=container, datapath=["my_geo:action_result.parameter.ip","my_geo:action_result.data.*.country_name"], action_results=results)

    my_geo_parameter_ip = [item[0] for item in my_geo_result_data]
    my_geo_result_item_1 = [item[1] for item in my_geo_result_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=my_geo_parameter_ip, message=my_geo_result_item_1, pin_style="blue", pin_type="card")

    return


def pin_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pin_3() called")

    my_geo_result_data = phantom.collect2(container=container, datapath=["my_geo:action_result.parameter.ip","my_geo:action_result.data.*.country_name"], action_results=results)

    my_geo_parameter_ip = [item[0] for item in my_geo_result_data]
    my_geo_result_item_1 = [item[1] for item in my_geo_result_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=my_geo_parameter_ip, message=my_geo_result_item_1, pin_style="red", pin_type="card")

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