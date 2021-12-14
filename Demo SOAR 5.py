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

    # call 'my_geolocate' block
    my_geolocate(container=container)

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

    phantom.act("geolocate ip", parameters=parameters, name="my_geolocate", assets=["maxmind"], callback=filter_out_internal_ips)

    return


def filter_out_internal_ips(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_out_internal_ips() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["my_geolocate:action_result.data.*.country_name", "!=", ""]
        ],
        name="filter_out_internal_ips:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


def format_list_of_ips_and_countries(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_list_of_ips_and_countries() called")

    template = """%%\nThe IP {0} is from {1}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_out_internal_ips:condition_1:my_geolocate:action_result.parameter.ip",
        "filtered-data:filter_out_internal_ips:condition_1:my_geolocate:action_result.data.*.country_name"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_list_of_ips_and_countries")

    pin_3(container=container)

    return


def pin_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pin_5() called")

    filtered_result_0_data_filter_out_internal_ips = phantom.collect2(container=container, datapath=["filtered-data:filter_out_internal_ips:condition_1:my_geolocate:action_result.data.*.country_name"])

    filtered_result_0_data___country_name = [item[0] for item in filtered_result_0_data_filter_out_internal_ips]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=filtered_result_0_data___country_name, message="All IPs are in USA or Spain", pin_style="blue", pin_type="card")

    return


def pin_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pin_3() called")

    format_list_of_ips_and_countries__as_list = phantom.get_format_data(name="format_list_of_ips_and_countries__as_list")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=format_list_of_ips_and_countries__as_list, message="IPs outside of USA and Spain", pin_style="red", pin_type="card")

    artifact_create_4(container=container)

    return


def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_2() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="or",
        conditions=[
            ["filtered-data:filter_out_internal_ips:condition_1:my_geolocate:action_result.data.*.country_name", "==", "United States"],
            ["filtered-data:filter_out_internal_ips:condition_1:my_geolocate:action_result.data.*.country_name", "==", "Spain"]
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        pin_5(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["filtered-data:filter_out_internal_ips:condition_1:my_geolocate:action_result.data.*.country_name", "!=", "United States"],
            ["filtered-data:filter_out_internal_ips:condition_1:my_geolocate:action_result.data.*.country_name", "!=", "Spain"]
        ],
        name="filter_2:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        format_list_of_ips_and_countries(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


def artifact_create_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("artifact_create_4() called")

    id_value = container.get("id", None)
    format_list_of_ips_and_countries = phantom.get_format_data(name="format_list_of_ips_and_countries")

    parameters = []

    parameters.append({
        "container": id_value,
        "name": format_list_of_ips_and_countries,
        "label": None,
        "severity": None,
        "cef_field": "myfield",
        "cef_value": format_list_of_ips_and_countries,
        "cef_data_type": None,
        "tags": None,
        "run_automation": None,
        "input_json": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_create", parameters=parameters, name="artifact_create_4")

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