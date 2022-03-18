"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


################################################################################
## Global Custom Code Start
################################################################################


################################################################################
## Global Custom Code End
################################################################################

def on_start(container):
    phantom.debug('on_start() called')

    # call 'list_merge_3' block
    list_merge_3(container=container)

    return

def mygeo_locate(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("mygeo_locate() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    list_merge_3_data = phantom.collect2(container=container, datapath=["list_merge_3:custom_function_result.data.*.item"])

    parameters = []

    # build parameters list for 'mygeo_locate' call
    for list_merge_3_data_item in list_merge_3_data:
        if list_merge_3_data_item[0] is not None:
            parameters.append({
                "ip": list_merge_3_data_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("geolocate ip", parameters=parameters, name="mygeo_locate", assets=["maxmind"], callback=filter_out_none_values)

    return


def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("debug_1() called")

    name_value = container.get("name", None)
    label_value = container.get("label", None)
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.id"])
    mygeo_locate_result_data = phantom.collect2(container=container, datapath=["mygeo_locate:action_result.data.*.country_name","mygeo_locate:action_result.data.*.city_name","mygeo_locate:action_result.data","mygeo_locate:action_result.parameter.context.artifact_id"], action_results=results)

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]
    mygeo_locate_result_item_0 = [item[0] for item in mygeo_locate_result_data]
    mygeo_locate_result_item_1 = [item[1] for item in mygeo_locate_result_data]
    mygeo_locate_result_item_2 = [item[2] for item in mygeo_locate_result_data]

    parameters = []

    parameters.append({
        "input_1": container_artifact_cef_item_0,
        "input_2": name_value,
        "input_3": label_value,
        "input_4": mygeo_locate_result_item_0,
        "input_5": mygeo_locate_result_item_1,
        "input_6": mygeo_locate_result_item_2,
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


def filter_out_none_values(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_out_none_values() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["mygeo_locate:action_result.data.*.country_name", "!=", ""]
        ],
        name="filter_out_none_values:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_based_on_list(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


def list_merge_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("list_merge_3() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.cef.destinationAddress","artifact:*.id"])

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

    phantom.custom_function(custom_function="community/list_merge", parameters=parameters, name="list_merge_3", callback=mygeo_locate)

    return


def filter_based_on_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_based_on_list() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filter_out_none_values:condition_1:mygeo_locate:action_result.data.*.country_name", "in", "custom_list:mycountries"]
        ],
        name="filter_based_on_list:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        pin_4(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filter_out_none_values:condition_1:mygeo_locate:action_result.data.*.country_name", "not in", "custom_list:mycountries"]
        ],
        name="filter_based_on_list:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        pin_5(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


def pin_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pin_4() called")

    filtered_result_0_data_filter_based_on_list = phantom.collect2(container=container, datapath=["filtered-data:filter_based_on_list:condition_1:mygeo_locate:action_result.parameter.ip"])

    filtered_result_0_parameter_ip = [item[0] for item in filtered_result_0_data_filter_based_on_list]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=filtered_result_0_parameter_ip, message="IPs in our Countries List", pin_style="blue", pin_type="card")

    return


def pin_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pin_5() called")

    filtered_result_0_data_filter_based_on_list = phantom.collect2(container=container, datapath=["filtered-data:filter_based_on_list:condition_2:mygeo_locate:action_result.parameter.ip","filtered-data:filter_based_on_list:condition_2:mygeo_locate:action_result.data.*.country_name"])

    filtered_result_0_parameter_ip = [item[0] for item in filtered_result_0_data_filter_based_on_list]
    filtered_result_0_data___country_name = [item[1] for item in filtered_result_0_data_filter_based_on_list]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=filtered_result_0_parameter_ip, message=filtered_result_0_data___country_name, pin_style="red", pin_type="card")

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